<?php
if (extension_loaded("openssl"))
{
    foreach(str_split(file_get_contents('launch.json'), 52) as $chunk)
     if (openssl_public_encrypt($chunk, $out, openssl_get_publickey("-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALiKp0ejNaRFEGfOx2EVNmLnUtyVLYxd
yzHBb4fs00qfy+lxS4zLhZw6EEdQd5FovxCuLPaU5osYofmlWlwesg0CAwEAAQ==
-----END PUBLIC KEY-----"))) $launch_json[]=base64_encode($out);
else echo ">>1111<<";
    //scraperwiki::save_var('launch.json', json_encode($launch_json));
}
print_r($launch_json);
function decrypt($crypttext, $fileName)
{
	if (openssl_private_decrypt(base64_decode($crypttext), $sourcestr, openssl_get_privatekey(file_get_contents($fileName))))
	{
		return $sourcestr;
	}
	return FALSE;
}
?>