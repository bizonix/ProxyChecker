<?php

$result = scraperwiki::sqliteexecute("select tbl_name, sql from sqlite_master where type='table'"); 
var_dump($result);
?>