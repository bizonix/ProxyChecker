<?php
include_once __DIR__.'/beaver/beaver.php';
$pdo = new \PDO('sqlite:ProxyDB.db');
$pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);  // Recommended
Beaver\Base::set_database($pdo);

class ProxyDB extends Beaver\Base
{
    protected static $_table = 'proxy';  // Required
    protected static $_pk = 'id';        // Optional
    public $id;
    public $ipIN;
    public $port;
    public $type;
    public $anonimity;
    public $ipOUT;
    public $country;
    public $Header;
    public $Cookie;
    public $Get;
    
    function __construct(){
        //FIX it
        if(filesize('ProxyDB.db')===0)
        {
            self::$_db->exec('CREATE TABLE `proxy` (
                 `id`        INTEGER    NOT NULL PRIMARY KEY AUTOINCREMENT,
                 `ipIN`      TEXT       NOT NULL,
                 `port`      INTEGER    NOT NULL,
                 `type`      TEXT       NOT NULL,
                 `anonimity` TEXT,
                 `ipOUT`     TEXT,
                 `country`   TEXT       NOT NULL DEFAULT \'N/A\',
                 `Cookie`    INTEGER    NOT NULL DEFAULT 0,
                 `Header`    INTEGER    NOT NULL DEFAULT 0,
                 `Get`       INTEGER    NOT NULL DEFAULT 0
            );
            ');
        }
    }
    
    function uniq($param){
        return self::select('WHERE ipIN = ? AND port = ?', $param);
    }
}

$obj = new ProxyDB();

foreach(array(
    'vpngeeksparser'=>"select ip,type,port from `swdata`",
    'proxynovaparser'=>"select ip,'HTTP',port from `proxynova`",
    'hide_my_ass_proxy_list_ip'=>"select ipaddress,_type,port from `hidemyass`",
    'hide_my_ass_proxy_list_ip_4'=>"select ipaddress,_type,port from `hidemyass`",
    'hide_my_ass_proxy_list_ip_5'=>"select ipaddress,_type,port from `hidemyass`",
    'hide_my_ass_proxy_list_ip_6'=>"select ipaddress,_type,port from `hidemyass`",
    'hide_my_ass_proxy_list_ip_7'=>"select ipaddress,_type,port from `hidemyass`",
    'hide_my_ass_proxy_list_ip_8'=>"select ipaddress,_type,port from `hidemyass`",
    'hide_my_ass_proxy_list_ip_9'=>"select ipaddress,_type,port from `hidemyass`",
    'proxyparser1'=>"select ipaddress,_type,port from `hidemyass`",
    
) as $user=>$querty){
    $count=$limit=0;$step=1000;
    echo 'Fetching from scraperwiki in user:"'.$user.'" ';
    do 
    {
        $Content = file_get_contents($uri = "http://api.scraperwiki.com/api/1.0/datastore/sqlite?format=jsonlist&name=".$user."&query=" . urlencode($querty . " limit $limit,$step"));
        $jsons = json_decode($Content, 1);
        $limit+= $step;
        foreach ($jsons['data'] as $json) 
        {
            if(count($obj->uniq(array($json[0],$json[2])))===0)
            {
                $obj->_flag_as_unsaved()->save(array(
                    'ipIN'=>$json[0],
                    'type'=>(strpos(strtolower($json[1]),'http')!==false)?'http':'socks',
                    'port'=>$json[2],
                ));
                $count++;
            }
        }
    }
    while (!empty($jsons['data']));
    echo 'Found '.$count.' new proxys'.PHP_EOL;
}
