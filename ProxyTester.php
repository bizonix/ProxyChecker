<?php
/*
Transparent Proxy

    REMOTE_ADDR: Proxy IP address
    HTTP_VIA: Proxy IP address/hostname and details - e.g. 1.1 proxy1.mydomain.net:3128 (squid/2.7.STABLE9)
    HTTP_X_FORWARDED_FOR: Your real IP address

Anonymous Proxy

    REMOTE_ADDR: Proxy IP address
    HTTP_VIA:   Proxy IP address/hostname and details - e.g. 1.1 proxy1.mydomain.net:3128 (squid/2.7.STABLE9) 
    HTTP_X_FORWARDED_FOR: blank

Elite Proxy

    REMOTE_ADDR: Proxy IP address
    HTTP_VIA: blank
    HTTP_X_FORWARDED_FOR: blank

*/
$_SERVER=array_merge($_SERVER,$_GET,$_POST,$_REQUEST);
if(isset($_GET['dbg']))
{
    print_r($_SERVER);
}
$x=new ProxyTester();
header('Content-type: application/json');
echo $x->Results();

class ProxyTester{
    const PT_None = 1;
    const PT_PName = 2;
    const PT_PInfo = 3;
    const PT_ClientIP = 4;
    
    private $PrivateIPs=array(
        '0.0.0.0/8',
        '10.0.0.0/8',
        '100.64.0.0/10',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '172.16.0.0/12',
        '192.0.0.0/24',
        '192.0.2.0/24',
        '192.168.0.0/16',
        '198.18.0.0/15',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '224.0.0.0/3',

        '224.0.0.0/4',
        '240.0.0.0/4',
    );
    private $ProxyEvidence = array(
         array('HTTP_VIA',                      self::PT_PName, true), // example.com:3128 (Squid/2.4.STABLE6)
         array('HTTP_PROXY_CONNECTION',         self::PT_None, true), //Keep-Alive
         array('HTTP_XROXY_CONNECTION',         self::PT_None, true), //Keep-Alive
         array('HTTP_X_FORWARDED_FOR',          self::PT_ClientIP, true), //X.X.X.X, X.X.X.X
         array('HTTP_X_FORWARDED',              self::PT_PInfo, true), //?
         array('HTTP_FORWARDED_FOR',            self::PT_ClientIP, true), //?
         array('HTTP_FORWARDED',                self::PT_PInfo, true), //by http://proxy.example.com:8080 (Netscape-Proxy/3.5)
         array('HTTP_X_COMING_FROM',            self::PT_ClientIP, true), //?
         array('HTTP_COMING_FROM',              self::PT_ClientIP, true),
                                                
         array('HTTP_CLIENT_IP',                self::PT_ClientIP, true), //X.X.X.X
         array('HTTP_PC_REMOTE_ADDR',           self::PT_ClientIP, true), //X.X.X.X
         array('HTTP_CLIENTADDRESS',            self::PT_ClientIP, true),
         array('HTTP_CLIENT_ADDRESS',           self::PT_ClientIP, true),
         array('HTTP_SP_HOST',                  self::PT_ClientIP, true),
         array('HTTP_SP_CLIENT',                self::PT_ClientIP, true),
         array('HTTP_X_ORIGINAL_HOST',          self::PT_ClientIP, true),
         array('HTTP_X_ORIGINAL_REMOTE_ADDR',   self::PT_ClientIP, true),
         array('HTTP_X_ORIG_CLIENT',            self::PT_ClientIP, true),
         array('HTTP_X_CISCO_BBSM_CLIENTIP',    self::PT_ClientIP, true),
         array('HTTP_X_AZC_REMOTE_ADDR',        self::PT_ClientIP, true),
         array('HTTP_10_0_0_0',                 self::PT_ClientIP, true),
         array('HTTP_PROXY_AGENT',              self::PT_PName, true),
         array('HTTP_X_SINA_PROXYUSER',         self::PT_ClientIP, true),
         array('HTTP_XXX_REAL_IP',              self::PT_ClientIP, true),
         array('HTTP_X_REMOTE_ADDR',            self::PT_ClientIP, true),
         array('HTTP_RLNCLIENTIPADDR',          self::PT_ClientIP, true),
         array('HTTP_REMOTE_HOST_WP',           self::PT_ClientIP, true),
         array('HTTP_X_HTX_AGENT',              self::PT_PName, true),
         array('HTTP_XONNECTION',               self::PT_None, true),
         array('HTTP_X_LOCKING',                self::PT_None, true),
         array('HTTP_PROXY_AUTHORIZATION',      self::PT_None, true),
         array('HTTP_MAX_FORWARDS',             self::PT_None, true),

         array('HTTP_X_FWD_IP_ADDR',            self::PT_ClientIP, true),

         array('HTTP_X_IWPROXY_NESTING',        self::PT_None, true),
         array('HTTP_X_TEAMSITE_PREREMAP',      self::PT_None, true), //http://www.example.com/example...
         array('HTTP_X_SERIAL_NUMBER',          self::PT_None, true),
         array('HTTP_CACHE_INFO',               self::PT_None, true),
         array('HTTP_X_BLUECOAT_VIA',           self::PT_PName, true),

//       array('HTTP_FROM',                     self::PT_ClientIP, true,'value'=>'/(\d{1,3}\.){3}\d{1,3}/'), //proxy is detected if header contains IP

         array('REMOTE_HOST',                   self::PT_None, true, 'value' => '/proxy.*\..*\..*/'),
         array('REMOTE_HOST',                   self::PT_None, true, 'value' => '/cache.*\..*\..*/'),

//       array('/^HTTP_X_.*/',                  self::PT_None, true),
         array('/^HTTP_X_.*/',                  self::PT_ClientIP, true),
         array('/^HTTP_PROXY.*/',               self::PT_None, true),
         array('/^HTTP_XROXY.*/',               self::PT_None, true),
         array('/^HTTP_XPROXY.*/',              self::PT_None, true),
         array('/^HTTP_VIA.*/',                 self::PT_None, false),
         array('/^HTTP_XXX.*/',                 self::PT_None, false),
         array('/^HTTP_XCACHE.*/',              self::PT_None, false)
     );
                    
    public function __construct($data=array()){
        
        if(!empty($data))
        {
            $_SERVER=$data;
        }
        if (!isset($_SERVER['REMOTE_ADDR'])) {
            $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        }
        $this->Proxy['detected']   = false;
        $this->Proxy['suspicious'] = false;
        $this->Proxy['name']       = NULL;
        $this->Proxy['info']       = array();
        $this->Proxy['headers']    = array();

        $this->IP['proxy'] = $_SERVER['REMOTE_ADDR'];
        $this->IP['client'] = '';

        $ips = '';
        $ipa = array($_SERVER['REMOTE_ADDR']);

        //INTERNAL USE - IP octet pattern
        $ipo = '(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)';
        //INTERNAL USE - IP pattern
        $this->ipFilter = "$ipo\\.$ipo\\.$ipo\\.$ipo";

        foreach ($this->ProxyEvidence as $Evidence){
             $tmp=$this->FindHeaders($Evidence[0]);
             foreach ($tmp as $hkey => $hvalue){
                  //make decision on proxy certainty data
                  $pkey= ($Evidence[2]===true) ? 'detected' : 'suspicious';
                  if (array_key_exists('value',$Evidence)){
                       if (preg_match($Evidence['value'],$hvalue)) $this->Proxy[$pkey]=true;
                  }else{
                       $this->Proxy[$pkey]=true;
                  }
                  //collect data about client IP, proxy name, other info
                  if ($Evidence[1]==self::PT_PName && empty($this->Proxy['name']))
                  {
                      $this->Proxy['name']=$hvalue;
                  }
                  if ($Evidence[1]==self::PT_ClientIP)
                  {
                      //ips will be parsed later; also headers can contain multiple IP addresses
                      $ips.=$hvalue.',';
                  }
                  if (($Evidence[1]==self::PT_PInfo)||($Evidence[1]==self::PT_PName))
                  {
                      $this->Proxy['info'][$hkey]=$hvalue;
                  }
                  if(($Evidence[1] == self::PT_None))
                  {
                      if(!empty($this->Proxy['info']) && !array_key_exists($hkey,$this->Proxy['info']))
                      {
                          $this->Proxy['None'][$hkey] = $hvalue;
                      }
                  }
                  $this->Proxy['headers'][$hkey]=$hvalue;
             }
        }
        //both 'detected' and 'suspicious' cannot be true
        if ($this->Proxy['detected'])
            $this->Proxy['suspicious'] = false;
        
        if (preg_match_all('/' . $this->ipFilter . '/', $ips, $match))
        {
            foreach ($match[0] as $value) {
                if (!in_array($value, $ipa))
                    $ipa[] = $value;
                foreach($this->PrivateIPs as $range)
                {
                    if($this->ipv4_in_range($value,$range) && empty($this->IP['client']))
                    {
                        $this->IP['client'] = $value;
                    }
                }
            }
        }
        $this->IP['all'] = implode(",", $ipa);
        if (empty($this->IP['client']))
            $this->IP['client'] = $this->IP['proxy'];
        $this->Proxy['anonymous'] = ($this->IP['client'] == $this->IP['proxy']) ? true : false;

    }
    function Results(){
        $res['REMOTE']=$this->IP['proxy'];
        if($this->Proxy['detected'] && $this->Proxy['anonymous'])
        {
            $res['type']= 'Anonymous';
        }elseif($this->Proxy['anonymous'] && !$this->Proxy['detected']){
            $res['type']=  'Elite';
        }elseif(!$this->Proxy['anonymous'] && $this->Proxy['detected']){
            $res['type']=  'Transparent';
        }else{
            $res['type']=  'NA';
        }
        foreach(array('HTTP_CUSTOM_HEADER','HTTP_COOKIE','QUERY_STRING') as $header)
            if(array_key_exists($header,$_SERVER))
            {
                parse_str($_SERVER[$header], $output);
                if(empty($output))continue;
                $tvalue=array_values($output);
                $tkeys=array_keys($output);
                if(!empty($tkeys[0]) && preg_match('#Custom(.*)Key#',$tkeys[0],$haedNames))
                {
                    $res[ $haedNames[1]]=true;
                }
                if(!empty($tvalue[0]))
                    $res['CustomKey']=$tvalue[0];
            }
        return json_encode($res);
    }
    function ipv4_in_range($ip, $range) {
        if (strpos($range, '/') !== false) {
            // $range is in IP/NETMASK format
            list($range, $netmask) = explode('/', $range, 2);
            if (strpos($netmask, '.') !== false) {
                // $netmask is a 255.255.0.0 format
                $netmask = str_replace('*', '0', $netmask);
                $netmask_dec = ip2long($netmask);
                return ( (ip2long($ip) & $netmask_dec) == (ip2long($range) & $netmask_dec) );
            } else {
                // $netmask is a CIDR size block
                // fix the range argument
                $x = explode('.', $range);
                while(count($x)<4) $x[] = '0';
                list($a,$b,$c,$d) = $x;
                $range = sprintf("%u.%u.%u.%u", empty($a)?'0':$a, empty($b)?'0':$b,empty($c)?'0':$c,empty($d)?'0':$d);
                $range_dec = ip2long($range);
                $ip_dec = ip2long($ip);
            
                # Strategy 1 - Create the netmask with 'netmask' 1s and then fill it to 32 with 0s
                #$netmask_dec = bindec(str_pad('', $netmask, '1') . str_pad('', 32-$netmask, '0'));
            
                # Strategy 2 - Use math to create it
                $wildcard_dec = pow(2, (32-$netmask)) - 1;
                $netmask_dec = ~ $wildcard_dec;
            
                return (($ip_dec & $netmask_dec) == ($range_dec & $netmask_dec));
            }
        } else {
            // range might be 255.255.*.* or 1.2.3.0-1.2.3.255
            if (strpos($range, '*') !==false) { // a.b.*.* format
                // Just convert to A-B format by setting * to 0 for A and 255 for B
                $lower = str_replace('*', '0', $range);
                $upper = str_replace('*', '255', $range);
                $range = "$lower-$upper";
            }
        
            if (strpos($range, '-')!==false) { // A-B format
                list($lower, $upper) = explode('-', $range, 2);
                $lower_dec = (float)sprintf("%u",ip2long($lower));
                $upper_dec = (float)sprintf("%u",ip2long($upper));
                $ip_dec = (float)sprintf("%u",ip2long($ip));
                return ( ($ip_dec>=$lower_dec) && ($ip_dec<=$upper_dec) );
            }
            return false;
        } 
    }
    
    function FindHeaders($name) {
        $result = array();
        if ($name[0] <> '/') {
            if (array_key_exists($name, $_SERVER)) {
                $result[$name] = $_SERVER[$name];
            }
        } else {
            foreach ($_SERVER as $key => $value) {
                if (preg_match($name, $key, $match)) $result[$key] = $value;
            }
        }
        return $result;
    }
}
