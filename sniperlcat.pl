#!/usr/bin/env perl
#
# SniperlCat 0.3-dev
#
# Versión 0.3:
#
#  - Los avisos los hace un script a parte
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
# Usa "libgtk2-notify-perl" para notificar al usuario
#  y "libnet-pcap-perl" y "libnetpacket-perl" para buscar paquetes sospechosos
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

my $appname = "Sniperlcat";
my $appver = "0.3-dev";
$timeout = 100;
$app_icon = "";

$network = "192.168.1.*";
$verbose = 0;
$cansino = 0;
$trigger = "./trigger";

my $go_back = 0;
my $arp_fill = 1;
my $file = "";
my $sltime = 60;
my $privileged = 0;
my $dev = "";
$r_thread = 0;

# Comprueba si es root
if ($< == 0){
    $privileged = 1;
}


# Todos los avisos van aquí
sub show_alert{
    $message = $_[0];
    open(T, "| $trigger")
    print T "$message";
    close(T);
}

# Se va al fondo
sub daemonize{
    $verbose = 0;
	umask 0;
	open STDIN, "</dev/null" || die $!;
	open STDOUT,">>/dev/null" || die $!;
	open STDERR, ">>/dev/null" || die $!;
	defined ($pid=fork) || die $!;
	exit if $pid;
	setsid || die $!;
}

# Muestra las opciones
sub show_help{
        print "$appname $appver\n";
        print "sniperlcat [-h]|[-d | -v ] [-nf] [-c] [-n <red>] [-f <descriptor de red>] [-p|-np] [-dv <interfaz>][-l <log>][-s <tiempo>]\n";
        print "-h  (--help): Muestra este mensaje\n";
        print "-d  (--daemonize): Se ejecuta de fondo\n";
        print "-nf (--no-fill): No llena la tabla de hosts (con nmap) antes de leerla\n";
        print "-c  (--cansino): Repite los avisos, aún los ya emitidos, en cada iteración\n";
        print "-v  (--verbose): Muestra más información por pantalla\n";
        print "-n  (--network): Especifica la red donde se ejecuta, por defecto 192.168.1.0/24\n";
        print "-dv (--device): Especifica la interfaz de red que se monitoreará\n";   
        print "-p  (--privileged): Se asumirán que es un usuario con privilegios\n";
        print "-np (--no-privileged): Se asumirán que es un usuario sin privilegios\n";
        print "-l  (--log): Se guardarán los avisos en un archivo\n";
        print "-s  (--sleep): Especifica el tiempo en segundos de \"descanso\" entre iteraciones (por defecto 60)\n";
}

# Comprueba los parámetros
my $i = 0;
while ($i <= $#ARGV){
    if (($ARGV[$i] eq "-d") || ($ARGV[$i] eq "--daemonize")){
        $go_back = 1;
    }
    elsif (($ARGV[$i] eq "-h") || ($ARGV[$i] eq "--help")){
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
            print "El archivo de log\n";
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
            break;
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

    $i++;
}

# Comprueba si usa el sniffer sin privilegios
if ((! $privileged) && ($dev ne "")){
    print "Son necesarios privilegios para el sniffer\n";
    exit(2);
}


daemonize if $go_back;

# Se activa el sniffer en otro hilo
if ($privileged){
    use Net::Pcap;
    use NetPacket::Ethernet;
    use NetPacket::IP;
    use NetPacket::TCP;
    if ($dev eq ""){
        print STDERR "No se ha especificado el dispositivo, hay disponibles ";
        my $err = "";
        my %devinfo = ();
        @devs = Net::Pcap::pcap_findalldevs(\%devinfo,\$err);
        print @devs.":\n";
        for my $dev (@devs) {
            print STDERR "$dev : $devinfo{$dev}\n"
        }
        exit(1);
    }
    use threads;
    print STDERR "Iniciando sniffer\n" if $verbose;
    $r_thread = threads->create(raw_sniffer, $dev); # Keeping it simple ^^
    unless (defined $r_thread){
        print STDERR "Error creando hilo de sniffer\ns";
    }
}

# Sniffer de packetes SYN de sockets RAW
sub raw_sniffer{
    my $filter_str = 'tcp and ip[6] & 127 == 0 and tcp[13] == 2'; # Flag SYN arriba y demás abajo, y DF OFF
    my $dev = $_[0];
    my $odev = Net::Pcap::open_live($dev, 1500, 0, 0, \$err);
    my $filter_compiled;
    unless (defined $odev){
        print STDERR "\nError [$err] abriendo interfaz en modo promiscuo\n";
        exit 2;
    }

    if (Net::Pcap::lookupnet($dev, \$address, \$netmask, \$err)) {
        die "Error [$err] al buscar información sobre $dev";
    }

    Net::Pcap::compile($odev, \$filter, $filter_str, 0, $netmask) &&
     die "Error compilando filtro Pcap";

    Net::Pcap::setfilter($odev, $filter) &&
     die 'Error aplicando el filtro';

    my $packet, $message, $ip, $ether, $src_ip;
    my %list, %header;
    while (1){
        Net::Pcap::pcap_next_ex($odev, \%header, \$packet);
        if (length($packet) <= 60){ # "Interesting" packet !! (normalmente 58)
            $ether = NetPacket::Ethernet::strip($packet);
            $ip = NetPacket::IP->decode($ether);
            $src_ip = $ip->{"src_ip"};
            if (defined $list->{$src_ip}){
                if (($list->{$src_ip} + $timeout) < time){
                    delete $list->{$src_ip};
                }
            }
            unless(defined $list->{$src_ip}){
                $tcp = NetPacket::TCP->decode($ip->{'data'});
                $message = "Paquete sospechoso desde [".$src_ip.
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
    `nmap $network -sP 2>/dev/null 1>/dev/null`;
}

# Carga la tabla arp de un archivo
sub load_arp_desc{
    my %tmplist = ();
    my $arp = $_[0];
    my @lines = split(/\n/,$arp);
    my $ip,$mac,$i = 0;
    my $max = @lines;
    while ($i < $max){
        # Extrae la IP
        @line = split(/ /,@lines[$i]);
        @ip = split(/\(/,$line[1]);
        @ip = split(/\)/,@ip[1]);
        $ip = @ip[0];

        # Y la MAC
        $mac = $line[3];

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
                            $message .= ", posiblemente spoofeado desde $tmpip";
                        }
                    }
                }
                print "$message\n" if $verbose;
                show_alert($message);
            }
        }
        else{
            # Si cambio la MAC
            if ($ip_list->{$ip} ne $mac){
                if (($lastlist->{$ip} ne $mac)||($cansino)){
                    my $message = "La MAC de $ip ha cambiado de [".$lastlist->{$ip}."] a [".$mac."]";
                    if ($mac ne "00:00:00:00:00"){ # Se suele utilizar para tapar
                                                   # despues de arp spoofing.
                                                   # No aporta nada
                        # Si la MAC está repetida, probablemente haya spoofing
                        foreach my $tmpip (keys %$ip_list){
                            if (($ip_list->{$tmpip} eq $mac) && ($tmpip ne $ip)){
                                $message .= ", posiblemente spoofeado desde $tmpip";
                            }
                        }
                    }
                    print "$message\n" if $verbose;
                    show_alert($message);
                }
            }
        }
    }
}

my %ip_list;
if ($file eq ""){
    if ($arp_fill){
        print STDERR "LLenando lista arp... " if $verbose;
        fill_arp_table;
        print STDERR "[OK]\n" if $verbose;
    }
    print STDERR "Leyendo tabla arp... " if $verbose;
    %ip_list = load_arp_list;
    print STDERR "[OK]\n" if $verbose;
}
else{
    local $/=undef;
    open MYFILE, "$file" or die "Couldn't open file: $!";
    binmode MYFILE;
    $arp = <MYFILE>;
    close MYFILE;
    %ip_list = load_arp_desc("$arp");
}

my $lastlist = \%ip_list;
while (1){
    if ($arp_fill){
        fill_arp_table;
    }
    my %tmplist = load_arp_list;
    check_list(\%ip_list,\%tmplist,$lastlist);
    $lastlist = \%tmplist;
    sleep $sltime;
}
