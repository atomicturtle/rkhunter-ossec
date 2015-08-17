<?php
$file = 'rkhunter';
$output = 'rootkit_files.txt';
$start = false;
$data = '';

// Parse command line arguments
$args = getopt("f:o:h");
foreach($args as $key => $value){
    switch ($key) {
        case "f":
            $file = $value;break;
        case "o":
            $output = $value;break;
        case "h":
            print("Convert rkhunter rootkit data into ossec (rootkit_files.txt).\n");
            print("\nExample:\n");
            print("  php conv.php -f /usr/local/rkhunter\n");
            print("\nOptional:\n");
            printf( "%-8s", "  -f" ); print("rkhunter script file (default: rkhunter)\n");
            printf( "%-8s", "  -o" ); print("output file (default: rootkit_files.txt)\n");
            exit;break;
    }
}

// Read names.txt file into an array
// Format: <alias> = <name>;<link>
$fd = fopen('names.txt', 'r') or die("can't open file: names.txt\n");
while (!feof($fd)){
    $buffer = fgets($fd);
    $l = trim($buffer);
    if ((substr($l, 0, 1) != '#') and ($l != '')){
        $p = explode('=', $l);
        if ($p[0] != null){
            $p2 = explode(';', $p[1]);
            $names[trim($p[0])] = array('name' => trim($p2[0]), 'path' => trim($p2[1]));
        }
    }
}
fclose($fd);

// Read rkhunter script file
$fd = fopen($file, 'r') or die("can't open file: ".$f."\n");
while (!feof($fd)){
    $buffer = fgets($fd);
    $l=trim($buffer);
    // Parse rootkit data and output in ossec format
    // Format: <file_name> ! <name> ::<link>
    if ($start){
        $p = strpos($l, '="');
        if ($p > -1) {
            $l2 = substr($l, 0, $p);
            $alias = substr($l, 0, strrpos($l2, "_"));
            $alias = strtolower($alias);
            $path = '';
            if (array_key_exists($alias, $names)){
                $path = $names[$alias]['path'];
                $alias = $names[$alias]['name'];
            }
        }
        $p = strpos($l, '${RKHROOTDIR}');
        if ($p > -1) {
            $f = substr($l, $p + 13, strlen($l) - 13 - $l);
            $f = trim($f,"\x22");
            $out = sprintf("%-34s", $f)."    ! ".$alias." ::".$path."\n";
            $data = $data.$out;
        }
    }
    // Rootkit data start
    if (substr($l, 0, 34) == "do_system_check_initialisation() {"){
        $start = true;
    }
    // Rootkit data end
    if (trim(substr($l, 0, 14)) == "# Evil strings"){
        $start = false;
    }
}
fclose ($fd);

// Save output to file
$fd = fopen($output, 'w') or die("can't open file: ".$output."\n");
fwrite($fd, $data);
fclose($fd);
?>
