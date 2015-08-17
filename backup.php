<?php

$rk = '';
$path = '';
$sData = '';
$names;

$arguments = getopt("f:h");
foreach($arguments as $key => $value){
    switch ($key) {
        case "f":
            read($value);break;
        case "h":
            print("Import rkhunter data into ossec.\n");
            print("\nExample:\n");
            print("  php conv.php -f rkhunter\n");
            print("\nRequired:\n");
            printf( "%-8s", "  -f" ); print("rkhunter script file\n");
            exit;break;
    }
}

function read($n){

    loadNames();

    global $sData;

    $start = false;

    $fd = fopen($n, "r");
    while (!feof($fd)){
        $buffer = fgets($fd);
        $line=trim($buffer);

        if ($start){
            parseLine($line);
        }
        if (substr($line, 0, 34) == "do_system_check_initialisation() {"){
            $start = true;
        }
        if (trim(substr($line, 0, 14)) == "# Evil strings"){
            $start = false;
        }
    }
    fclose ($fd);

    saveFile('out.txt', $sData);
}

function parseLine($l){
    global $rk,$sData,$names,$path;

    $p = strpos($l, '="');
    if ($p > -1) {
        $l2 = substr($l, 0, $p);
        $rk = substr($l, 0, strrpos($l2, "_"));
        $rk = strtolower($rk);
        $path = '';
        if (array_key_exists($rk, $names)){
            $path = $names[$rk]['path'];
            $rk = $names[$rk]['name'];
        }
    }

    $p = strpos($l, '${RKHROOTDIR}');
    if ($p > -1) {
        $f = substr($l, $p + 13, strlen($l) - 13 - $l);
        $f = trim($f,"\x22");
        $out = sprintf( "%-34s", $f )."    ! ".$rk." ::".$path."\n";
        $sData = $sData.$out;
    }
}

function saveFile($f, $d){
    $fh = fopen($f, 'w') or die("can't open file");
    fwrite($fh, $d);
    fclose($fh);
}

function loadNames(){
    global $names;

    $fd = fopen("names.txt", "r");

    while (!feof($fd)){
        $buffer = fgets($fd);
        $line = trim($buffer);
        if ((substr($line, 0, 1) != '#') and ($line != '')){
            $parts = explode('=', $line);
            if ($parts[0] != null){
                $parts2 = explode(';', $parts[1]);
                $names[trim($parts[0])] = array('name' => trim($parts2[0]), 'path' => trim($parts2[1]));
            }
        }
    }
    fclose($fd);
}
?>
