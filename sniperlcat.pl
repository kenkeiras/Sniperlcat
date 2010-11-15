#!/usr/bin/env perl
#
# SniperlCat 0.3.1
#
# Versión 0.3.1:
#
#  - Pasado a perl estricto
#  - Corregido bug en el parseo de flags en la línea de comandos
#
# Versión 0.3:
#
#  - Los avisos los hace un script a parte
#  - Corregido al bug que lo volvia paranoico al cerrar el dispositivo
#  - Añadida la opción de puerto a la escucha
#
# Versión 0.2:
#  - Los avisos los hace una función a parte
#  - Añadido archivo de log
#  - Añadida detección de paquetes SYN sospechosos de sockets RAW =)}
#   (para usuarios con privilegios)
#
# Versión 0.1:
#  - Detección de nuevos hosts
#  - Detección de nuevos hosts spoofeados
#  - Detección de cambios de MAC
#  - Detección de cambios de MAC debidos a spoofing
#
# Usa "libnet-pcap-perl" y "libnetpacket-perl" para buscar paquetes
# y "nmap" para llenar la tabla ARP
#
##############################################################################
#  Copyright (C) 2010 Kenkeiras <kenkeiras@gmail.com>
#
#  This program is free software. It comes without any warranty, to
#  the extent permitted by applicable law. You can redistribute it
#  and/or modify it under the terms of the Do What The Fuck You Want
#  To Public License, Version 2, as published by Sam Hocevar. 
#
#  See http://sam.zoy.org/wtfpl/COPYING for more details.
##############################################################################

use threads; # Multihilo 
use Socket;  # Conexiones de red
use strict;  # Perl estricto
use POSIX qw(setsid); # setsid (para la daemonización)

my $appname = "Sniperlcat"; # Nombre del script
my $appver = "0.3.1";       # Versión del script
our $timeout = 60;          # Timeout

our $network = "192.168.1.*";  # Red que se escaneará con nmap
our $verbose = 0;              # Se mostrará información por el terminal
our $cansino = 0;              # Se repetirán los avisos
our $trigger = "./trigger.sh"; # Comando que se activará para mandar mensajes
our $log = "";                 # Archivo donde se guardará el log
our $backlog = 10;             # Número de conexiones entrantes concurrentes

my $arp_fill = 1;   # Se llenará la tabla ARP (con nmap)
my $file = "";      # Tabla ARP predefinida
my $sltime = 60;    # Tiempo que se esperará entre cada comprobación
my $privileged = 0; # Si el usuario tiene privilegios de root
my $dev = "";       # Dispositivo para sniffar paquetes
my $r_thread = 0;   # [placeholder]

# Comprueba si es root
if ($< == 0){
    $privileged = 1;
}

# Muestra la lista de dispositivos disponibles
sub selectdev{
        print STDERR "No se ha especificado el dispositivo, hay disponibles ";
        my $err = "";     # Error
        my %devinfo = (); # Información del dispositivo
        my @devs;         # Dispositivos

        # Obtiene la lista de todos los dispositivos
        @devs = Net::Pcap::pcap_findalldevs(\%devinfo,\$err);

        # Y la muestra
        print @devs.":\n";
        for my $dev (@devs) {
            print STDERR "$dev : $devinfo{$dev}\n"
        }
}

# Todos los avisos van aquí
sub show_alert{
    my $message = $_[0];                   # Mensaje que se enviará
    print STDERR "$message\n" if $verbose;
    open(T, "| $trigger");  # Activa el trigger
    print T "$message\n";   # Le envía el mensaje
    close(T);
    if ("$log" ne "" ){ # Si se está guardando log
        open(LOG, ">>$log");     # Añade el mensaje
        print LOG "$message\n";
        close(LOG);
    }
}

# Se va al fondo
sub daemonize{
    umask 0; 
    open STDIN, "</dev/null" || die $!;
    open STDOUT,">>/dev/null" || die $!;
    open STDERR, ">>/dev/null" || die $!;
    defined (my $pid = fork) || die $!;
    exit if $pid;
    setsid || die $!;
}

# Escucha el puerto esperando conexiones
sub port_wait{
    my $msg = $_[0];  # Mensaje que se enviará
    my $port = $_[1]; # Puerto que se 
    my $proto = getprotobyname('tcp');
    socket(sock, PF_INET, SOCK_STREAM, $proto) || die "socket:$!";
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)) ||\
         die "setsockopt: $!";

    bind(sock, sockaddr_in($port, INADDR_ANY)) || die "bind: $!";
    listen(sock, $backlog) || die "listen: $!";
    my $l = length($msg) > 0;
    my $lastip = 0;
    my $lastconn = 0;
    my $lastport = 0;
    my $client;
    my $alert;
    while (1){
        $client = accept(nsock, sock);
        my($rport, $remote) = sockaddr_in ($client);
        if ($l){
            print nsock "$msg\n";
        }
        if (($lastip != $remote) || (($lastconn + $timeout) < time)){
            $lastip = $remote;
            $lastconn = time;
            $alert = "Puerto [$port] conectado desde [".inet_ntoa($remote)."]";
            show_alert($alert);
            print "->"."Puerto [$port] conectado desde [".inet_ntoa($remote)."]"."\n";
        }

        close(nsock);
    }
}

# Muestra las opciones
sub show_help{
        print "$appname $appver\n";
        print "sniperlcat [-h]|[-d | -v ] [-nf] [-c] [-n <red>] [-f <descriptor de red>] [-p|-np] [-dv <interfaz>] [-l <log>] [-s <tiempo>] [-t <trigger>] [-p <puerto> <mensaje>]\n";
        print "-h  (--help): Muestra este mensaje\n";
        print "-d  (--daemonize): Se ejecuta de fondo\n";
        print "-nf (--no-fill): No llena la tabla de hosts (con nmap) antes de leerla\n";
        print "-c  (--cansino): Repite los avisos, aún los ya emitidos, en cada iteración\n";
        print "-v  (--verbose): Muestra más información por pantalla\n";
        print "-n  (--network): Especifica la red donde se ejecuta, por defecto 192.168.1.0/24\n";
        print "-f  (--file): Especifica el descriptor de red (como salida de arp -a)";
        print "-dv (--device): Especifica la interfaz de red que se monitoreará\n";   
        print "-p  (--privileged): Se asumirán que es un usuario con privilegios\n";
        print "-np (--no-privileged): Se asumirán que es un usuario sin privilegios\n";
        print "-l  (--log): Se guardarán los avisos en un archivo\n";
        print "-s  (--sleep): Especifica el tiempo en segundos de \"descanso\" entre iteraciones (por defecto 60)\n";
        print "-t  (--trigger) Especifica el trigger que se disparará en las alertas\n";
        print "-pt  (--port): Especifica un puerto para esperar conexiones y el mensaje que envia\n";
}

# Comprueba los parámetros
my $i = 0;

while ($i <= $#ARGV){
    if (($ARGV[$i] eq "-h") || ($ARGV[$i] eq "--help")){
        show_help;
        exit 0;
    }
    elsif (($ARGV[$i] eq "-v") || ($ARGV[$i] eq "--verbose")){
        $verbose = 1;
    }
    elsif (($ARGV[$i] eq "-c") || ($ARGV[$i] eq "--cansino")){
        $cansino = 1;
    }
    elsif (($ARGV[$i] eq "-nf") || ($ARGV[$i] eq "--no-fill")){
        $arp_fill = 0;
    }
    elsif (($ARGV[$i] eq "-p") || ($ARGV[$i] eq "--privileged")){
        $privileged = 1;
    }
    elsif (($ARGV[$i] eq "-np") || ($ARGV[$i] eq "--no-privileged")){
        $privileged = 0;
    }
    elsif (($ARGV[$i] eq "-l") || ($ARGV[$i] eq "--log")){
        $i++;
        if ($i > $#ARGV){
            print "No se ha especificado el archivo de log\n";
            show_help;
            exit 1;
        }
        $log = $ARGV[$i];
    }
    elsif (($ARGV[$i] eq "-n") || ($ARGV[$i] eq "--network")){
        $i++;
        if ($i > $#ARGV){
            print "No se ha especificado la red\n";
            show_help;
            exit 1;
        }
        $network = $ARGV[$i];
    }
    elsif (($ARGV[$i] eq "-dv") || ($ARGV[$i] eq "--device")){
        $i++;
        if ($i > $#ARGV){
            selectdev();
            exit(1);
        }
        $dev = $ARGV[$i];
    }
    elsif (($ARGV[$i] eq "-f") || ($ARGV[$i] eq "--file")){
        $i++;
        if ($i > $#ARGV){
            print "No se ha especificado el archivo de red\n";
            show_help;
            exit 1;
        }
        $file = $ARGV[$i];
    }
    elsif (($ARGV[$i] eq "-s") || ($ARGV[$i] eq "--sleep")){
        $i++;
        if ($i > $#ARGV){
            print "No se ha especificado el tiempo\n";
            show_help;
            exit 1;
        }
        $sltime = $ARGV[$i];
    }
    elsif (($ARGV[$i] eq "-t") || ($ARGV[$i] eq "--trigger")){
        $i++;
        if ($i > $#ARGV){
            print "No se ha especificado el trigger\n";
            show_help;
            exit 1;
        }
        $trigger = $ARGV[$i];
    }
    $i++;
}

$i = 0;
# Y si hay que daemonizarlo para evitar problemas con los hilos
while ($i <= $#ARGV){ 
    if    (($ARGV[$i] eq "-d") || ($ARGV[$i] eq "--daemonize")){
        daemonize();
    }
    $i++;
}

# Por último los flags que lanzan hilos
$i = 0;
while ($i <= $#ARGV){
    if (($ARGV[$i] eq "-pt") || ($ARGV[$i] eq "--port")){
        $i++;
        if ($i > $#ARGV){
            print "No se ha especificado el puerto\n";
            show_help;
            exit 1;
        }
        my $port = $ARGV[$i];

        $i++;
        if ($i > $#ARGV){
            print "No se ha especificado el mensaje\n";
            show_help;
            exit 1;
        }
        my $msg = $ARGV[$i];

        $r_thread = threads->create('port_wait', ($msg, $port)); # Keeping it simple ^^
        unless (defined $r_thread){
            print STDERR "Error creando hilo de escucha en el puerto\n";
            exit(2);
        }
    }

    $i++;
}

# Comprueba si usa el sniffer sin privilegios
if ((! $privileged) && ($dev ne "")){
    print "Son necesarios privilegios para el sniffer\n";
    exit(2);
}

# Se activa el sniffer en otro hilo
if ($privileged){
    use Net::Pcap;
    use NetPacket::Ethernet;
    use NetPacket::IP;
    use NetPacket::TCP;
    if ($dev eq ""){
        selectdev();
        exit(1);
    }
    print STDERR "Iniciando sniffer\n" if $verbose;
    $r_thread = threads->create('raw_sniffer', $dev); #Crea un hilo de sniffer
    unless (defined $r_thread){
        print STDERR "Error creando hilo de sniffer\n";
    }
}

# Sniffer de packetes SYN de sockets RAW
sub raw_sniffer{
    my $err;
    # Flag SYN arriba y demás abajo, y DF OFF
    my $filter_str = 'tcp and ip[6] & 127 == 0 and tcp[13] == 2'; 
    my $dev = $_[0];
    my $odev = Net::Pcap::open_live($dev, 1500, 0, 0, \$err);
    my $filter_compiled;
    my $address;
    my $netmask;
    my $filter;
    unless (defined $odev){
        print STDERR "\nError [$err] abriendo interfaz en modo promiscuo\n";
        exit 2;
    }

    # Lee los datos de la red
    if (Net::Pcap::lookupnet($dev, \$address, \$netmask, \$err)) {
        die "Error [$err] al buscar información sobre $dev";
    }
    
    # Compila el filtro Pcap
    Net::Pcap::compile($odev, \$filter, $filter_str, 0, $netmask) &&
     die "Error compilando filtro Pcap";

    # Aplica el filtro al dispositivo
    Net::Pcap::setfilter($odev, $filter) &&
     die 'Error aplicando el filtro';

    my $packet;
    my $list;

    my %header;
    while (1){
        # Lee el siguiente paquete
        Net::Pcap::pcap_next_ex($odev, \%header, \$packet);

        if (length($packet) < 1){ # Si se desconecta el interfaz
            do{ sleep $timeout;
                $odev = Net::Pcap::open_live($dev, 1500, 0, 0, \$err);
            }while(! defined $odev);

            # Lee los datos de la red
            if (Net::Pcap::lookupnet($dev, \$address, \$netmask, \$err)) {
                die "Error [$err] al buscar información sobre $dev";
            }
            
            # Compila el filtro Pcap
            Net::Pcap::compile($odev, \$filter, $filter_str, 0, $netmask) &&
             die "Error compilando filtro Pcap";

            # Aplica el filtro al dispositivo
            Net::Pcap::setfilter($odev, $filter) &&
             die 'Error aplicando el filtro';
        }
        elsif (length($packet) < 60){# Paquete TCP extraño

            my $ether = NetPacket::Ethernet::strip($packet); # Lee la trama
            my $ip = NetPacket::IP->decode($ether);  # Extrae el paquete IP
            my $src_ip = $ip->{"src_ip"};
            if (defined $list->{$src_ip}){ # Si es una IP ya "conocida"
                                           # comprueba si ya pasó suficiente
                if (($list->{$src_ip} + $timeout) < time){ 
                    delete $list->{$src_ip};
                }
            }
            unless(defined $list->{$src_ip}){
                my $tcp = NetPacket::TCP->decode($ip->{'data'});
                my $message = "Paquete sospechoso desde [".$src_ip.
                    ":".$tcp->{"src_port"}."] a [".$ip->{"dest_ip"}.":".
                    $tcp->{"dest_port"}."]";
                show_alert($message);
                $list->{$src_ip} = time;
            }
        }
    }
    Net::Pcap::close($odev); # Aunque nunca llegará aquí
}

# LLena la tabla arp con nmap
sub fill_arp_table{
    `nmap $network -sP -n 2>/dev/null 1>/dev/null`;
}

# Carga la tabla arp de un archivo
sub load_arp_desc{
    my %tmplist = ();
    my $arp = $_[0];
    my @lines = split(/\n/,$arp);
    my $i = 0;
    my $max = @lines;
    while ($i < $max){
        # Extrae la IP
        my @line = split(/ /,@lines[$i]);
        my @ip = split(/\(/,$line[1]);
        @ip = split(/\)/,@ip[1]);
        my $ip = @ip[0];

        # Y la MAC
        my $mac = $line[3];

        # Y se introduce en la lista si es una MAC válida
        if (substr("$mac", 0, 1) ne "<"){
            $tmplist{"$ip"} = "$mac";
        }
        $i++;
    }
    return %tmplist;
}

# Carga la tabla arp
sub load_arp_list{
    my $arp = `arp -an`;
    return load_arp_desc($arp);
}

# Hace las comprobaciones
sub check_list{
    my $ip_list = $_[0];
    my $tmplist = $_[1];
    my $lastlist = $_[2];
    foreach my $ip (keys %$tmplist){
        my $mac = $tmplist->{$ip};

        # Si es un host nuevo
        if (!exists $ip_list->{$ip} ) {
            if ((!exists $lastlist->{$ip}) || ($cansino)){
                my $message = "Equipo desconocido en la red: $ip [$mac]";
                if ($mac ne "00:00:00:00:00"){ # Se suele utilizar para tapar
                                               # despues de arp spoofing.
                                               # No aporta nada
                    # Si la MAC está repetida, probablemente haya spoofing
                    foreach my $tmpip (keys %$ip_list){
                        if (($ip_list->{$tmpip} eq $mac) && ($tmpip ne $ip)){
                            $message.=", posiblemente spoofeado desde $tmpip";
                        }
                    }
                }
                show_alert($message);
            }
        }
        else{
            # Si cambio la MAC
            if ($ip_list->{$ip} ne $mac){
                if (($lastlist->{$ip} ne $mac)||($cansino)){
                    my $message = "La MAC de $ip ha cambiado de [".\
                        $lastlist->{$ip}."] a [".$mac."]";

                    if ($mac ne "00:00:00:00:00"){ # Se suele utilizar para
                                                   #  tapar despues de arp 
                                                   # spoofing. No aporta nada.

                        # Si la MAC está repetida, probablemente haya spoofing
                        foreach my $tmpip (keys %$ip_list){
                            if (($ip_list->{$tmpip} eq $mac) &&\
                                 ($tmpip ne $ip)){
                                $message .= \
                                    ", posiblemente spoofeado desde $tmpip";
                            }
                        }
                    }
                    show_alert($message);
                }
            }
        }
    }
}

my %ip_list;
if ($file eq ""){ # Si no se especifica una tabla ARP
    if ($arp_fill){
        print STDERR "LLenando lista arp... " if $verbose;
        fill_arp_table;
        print STDERR "[OK]\n" if $verbose;
    }
    print STDERR "Leyendo tabla arp... " if $verbose;
    %ip_list = load_arp_list;
    print STDERR "[OK]\n" if $verbose;
}
else{ # Si se especifica la tabla ARP
    local $/=undef;
    open MYFILE, "$file" or die "Couldn't open file: $!";
    binmode MYFILE;
    my $arp = <MYFILE>;
    close MYFILE;
    %ip_list = load_arp_desc("$arp");
}

my $lastlist = \%ip_list;

while (1){
    if ($arp_fill){
        fill_arp_table;
    }
    my %tmplist = load_arp_list;               # Carga la tabla ARP actual
    check_list(\%ip_list,\%tmplist,$lastlist); # Comprueba la nueva tabla
    $lastlist = \%tmplist;
    sleep $sltime;
}
