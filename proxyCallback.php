<?php


DEFINE ("PATH_CALLBACK_FILE", "proxy_tickets/");

if (!empty($_GET['pgtIou']) && !empty($_GET['pgtId'])) {
    if (preg_match('/PGTIOU-[\.\-\w]/', $_GET['pgtIou'])) {
        if (preg_match('/[PT]GT-[\.\-\w]/', $_GET['pgtId'])) {
            $pgt_iou = $_GET['pgtIou'];
            $pgt = $_GET['pgtId'];
            //Init storage...
            pgtStorage($pgt,$pgt_iou);
            
        } else {
            //TODO: control errores, trazas...
            //phpCAS::error('PGT format invalid' . $_GET['pgtId']);
            //phpCAS::traceExit('PGT format invalid' . $_GET['pgtId']);
        }
    } else {
        //TODO: control errores, trazas...
        //phpCAS::error('PGT format invalid' . $_GET['pgtId']);
        //phpCAS::traceExit('PGT format invalid' . $_GET['pgtId']);
    }
}
else {
    //TODO: ERROR
    //No found pgtid or pgtiou params on callback...
}

clearOldPgts();

function pgtStorage($pgt, $pgtiou) {
    $filename = $pgtiou . ".txt";
    if (!file_exists(PATH_CALLBACK_FILE . $filename)) {
        $f = fopen(PATH_CALLBACK_FILE . $filename, "w");
        if ($f) {
            if (fputs($f, $pgt) === FALSE) {
                //controlar error...
            }
            fclose($f);
        } else {
            //controlar error...
        }
    }
}

function clearOldPgts() {
    $timeExpired = 5; //in secons.
    $dir = "proxy_tickets/";
    $handle = @opendir($dir);
    if ($handle) {
        $entry = @readdir($handle);
        while (false !== ($entry)) {
            if ($entry != "." && $entry != "..") {
                $ext = pathinfo($entry, PATHINFO_EXTENSION);
                $filename = pathinfo($entry, PATHINFO_FILENAME);
                $filePath = implode("", array(PATH_CALLBACK_FILE, $entry));
                if ($ext == "txt" && preg_match('/PGTIOU-[\.\-\w]/', $filename)) {
                    $creationDate = strtotime(date("F d Y H:i:s.", filectime($filePath)));
                    $actualDate = strtotime(date("F d Y H:i:s."));
                    $timeElapsed = $actualDate - $creationDate;

                    if ($timeElapsed > $timeExpired) {
                        if (unlink($filePath)) {
                            error_log(sprintf('The file "%s" has been deleted due to maintenance task.', $entry));
                        };
                    }
                }
            }
            $entry = @readdir($handle);
        }
        closedir($handle);
    } else {
        //TODO: manejar error: no ha sido posible abrir el directorio %s, PATH_CALLBACK_FILE.
    }
}
