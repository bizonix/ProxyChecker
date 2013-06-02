<?php
include_once __DIR__.'/beaver/db.php';
include_once __DIR__.'/beaver/beaver.php';

define('STORAGE_DBFILE', __DIR__.'/ProxyDB002.db');
defined('DS') ? null : define('DS', DIRECTORY_SEPARATOR);
defined('EOL') ? null : define('EOL', PHP_EOL);


class ProxyDB extends Beaver\Base
{
    protected static $_last_error = '';
    protected static $_table = 'proxy';  // Required
    protected static $_pk = 'ipIN';        // Optional
//    public $id;
    public $ipIN;
    public $port;
    public $type;
    public $level;
    public $ipOUT;
    public $country='N/A';
    public $Header=0;
    public $Cookie=0;
    public $Get=0;
    
    static public $CountProxys;
    
    public static function install()
    {
        $TableStructure="CREATE TABLE `proxy` (
--               `id`      INTEGER  PRIMARY KEY AUTOINCREMENT,
                 `ipIN`    TEXT     NOT NULL,
                 `port`    INTEGER  NOT NULL,
                 `type`    TEXT     NOT NULL,
                 `level`   TEXT,    
                 `ipOUT`   TEXT,    
                 `country` TEXT     DEFAULT 'N/A',
                 `Cookie`  INTEGER  DEFAULT 0,
                 `Header`  INTEGER  DEFAULT 0,
                 `Get`     INTEGER  DEFAULT 0
            )";
        \Common\DB::query($TableStructure);
    }
    public static function is_installed()
    {
        try
        {
            self::$CountProxys = \Common\DB::query('SELECT count(*) FROM proxy')->fetchColumn();
            return true;
        }
        catch (\PDOException $e)
        {
            self::$_last_error = $e->getMessage();
            return false;
        }
    }
    
    function is_uniq($param){
        return self::select('WHERE ipIN = ? AND port = ?', $param);
    }
    function is_valid_ip($ip) 
    {
        if (function_exists('filter_var')) 
        {
            return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
        }
        else
        {
            //Regex constant for validateing IPv4
            return preg_match('@^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$@', $ip);
        }
    }
    
}

\Common\DB::initialize(STORAGE_DBFILE);
\Common\DB::query('PRAGMA foreign_keys = ON');  // SQLite needs this.
\Common\DB::get_pdo()->setAttribute(\PDO::ATTR_CASE,PDO::CASE_NATURAL);
//\Common\DB::get_pdo()->setAttribute(\PDO::ATTR_PERSISTENT,true);

\Beaver\Base::set_database(\Common\DB::get_pdo());

//var_dump (\Common\DB::get_pdo()->getAttribute(\PDO::ATTR_PERSISTENT));

if (!\ProxyDB::is_installed()) \ProxyDB::install();
else echo \ProxyDB::$CountProxys, " proxys exists in DB".EOL;

$obj = new \ProxyDB();

foreach(array(
    'vpngeeksparser'             =>"select ip,type,port from `swdata`",
    'proxynovaparser'            =>"select ip,'HTTP',port from `proxynova`",
    'hide_my_ass_proxy_list_ip'  =>"select ipaddress,_type,port from `hidemyass`",
    'hide_my_ass_proxy_list_ip_4'=>"select ipaddress,_type,port from `hidemyass`",
    'hide_my_ass_proxy_list_ip_5'=>"select ipaddress,_type,port from `hidemyass`",
    'hide_my_ass_proxy_list_ip_6'=>"select ipaddress,_type,port from `hidemyass`",
    'hide_my_ass_proxy_list_ip_7'=>"select ipaddress,_type,port from `hidemyass`",
    'hide_my_ass_proxy_list_ip_8'=>"select ipaddress,_type,port from `hidemyass`",
    'hide_my_ass_proxy_list_ip_9'=>"select ipaddress,_type,port from `hidemyass`",
    'proxyparser1'               =>"select ipaddress,_type,port from `hidemyass`",
    
) as $user=>$querty){
    $count=$limit=0;$step=1000;
    echo 'Fetching from scraperwiki in user:"'.$user.'" '.EOL;
    do 
    {
        $Content = file_get_contents($uri = "http://api.scraperwiki.com/api/1.0/datastore/sqlite?format=jsonlist&name=".$user."&query=" . rawurlencode($querty . " limit $limit,$step"));
        $jsons   = json_decode($Content, 1);
        $limit  += $step;
        if(!isset($jsons['data']))
        {
            $limit  -= $step;
            echo "Error:$uri".EOL;
            continue;
        }
        foreach ($jsons['data'] as $json) 
        {
            $obj->ipIN=$json[0];
            $obj->type=(strpos(strtolower($json[1]),'http')!==false)?0:1;
            $obj->port=$json[2];
            
            if($obj->is_valid_ip($obj->ipIN) && !count($obj->is_uniq(array($obj->ipIN,$obj->port))))
            {
                $obj->_flag_as_unsaved()->save();
                $count++;
            }
        }
    }
    while (!empty($jsons['data']));
    echo 'Found '.$count.' new proxys'.EOL;
}
