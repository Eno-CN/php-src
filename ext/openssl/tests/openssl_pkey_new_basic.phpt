--TEST--
openssl_pkey_new() basic usage tests
--EXTENSIONS--
openssl
--SKIPIF--
<?php
if (!defined('OPENSSL_KEYTYPE_EC')) die("skip no EC available");
?>
--FILE--
<?php
function openssl_pkey_test_cmp($expected, $bin_key) {
    var_dump(strcasecmp(ltrim($expected, '0'), bin2hex($bin_key)));
}

// RSA
$nhex = "BBF82F090682CE9C2338AC2B9DA871F7368D07EED41043A440D6B6F07454F51F" .
        "B8DFBAAF035C02AB61EA48CEEB6FCD4876ED520D60E1EC4619719D8A5B8B807F" .
        "AFB8E0A3DFC737723EE6B4B7D93A2584EE6A649D060953748834B2454598394E" .
        "E0AAB12D7B61A51F527A9A41F6C1687FE2537298CA2A8F5946F8E5FD091DBDCB";

$ehex = "11";
$dhex = "A5DAFC5341FAF289C4B988DB30C1CDF83F31251E0668B42784813801579641B2" .
        "9410B3C7998D6BC465745E5C392669D6870DA2C082A939E37FDCB82EC93EDAC9" .
        "7FF3AD5950ACCFBC111C76F1A9529444E56AAF68C56C092CD38DC3BEF5D20A93" .
        "9926ED4F74A13EDDFBE1A1CECC4894AF9428C2B7B8883FE4463A4BC85B1CB3C1";

$phex = "EECFAE81B1B9B3C908810B10A1B5600199EB9F44AEF4FDA493B81A9E3D84F632" .
        "124EF0236E5D1E3B7E28FAE7AA040A2D5B252176459D1F397541BA2A58FB6599";

$qhex = "C97FB1F027F453F6341233EAAAD1D9353F6C42D08866B1D05A0F2035028B9D86" .
        "9840B41666B42E92EA0DA3B43204B5CFCE3352524D0416A5A441E700AF461503";

$dphex = "11";
$dqhex = "11";
$qinvhex = "b06c4fdabb6301198d265bdbae9423b380f271f73453885093077fcd39e2119f" .
           "c98632154f5883b167a967bf402b4e9e2e0f9656e698ea3666edfb25798039f7";

$rsa= openssl_pkey_new(array(
    'rsa' => array(
        'n' => hex2bin($nhex),
        'e' => hex2bin($ehex),
        'd' => hex2bin($dhex),
        'p' => hex2bin($phex),
        'q' => hex2bin($qhex),
        'dmp1' => hex2bin($dphex),
        'dmq1' => hex2bin($dqhex),
        'iqmp' => hex2bin($qinvhex),
    )
));
$details = openssl_pkey_get_details($rsa);
$rsa_details = $details['rsa'];
openssl_pkey_test_cmp($nhex, $rsa_details['n']);
openssl_pkey_test_cmp($ehex, $rsa_details['e']);
openssl_pkey_test_cmp($dhex, $rsa_details['d']);
openssl_pkey_test_cmp($phex, $rsa_details['p']);
openssl_pkey_test_cmp($qhex, $rsa_details['q']);
openssl_pkey_test_cmp($dphex, $rsa_details['dmp1']);
openssl_pkey_test_cmp($dqhex, $rsa_details['dmq1']);
openssl_pkey_test_cmp($qinvhex, $rsa_details['iqmp']);
echo "\n";

// DSA
$phex = '00f8000ae45b2dacb47dd977d58b719d097bdf07cb2c17660ad898518c08' .
        '1a61659a16daadfaa406a0a994c743df5eda07e36bd0adcad921b77432ff' .
        '24ccc31e782d647e66768122b578857e9293df78387dc8b44af2a4a3f305' .
        '1f236b1000a3e31da489c6681b0031f7ec37c2e1091bdb698e7660f135b6' .
        '996def90090303b7ad';

$qhex = '009b3734fc9f7a4a9d6437ec314e0a78c2889af64b';

$ghex = '00b320300a0bc55b8f0ec6edc218e2185250f38fbb8291db8a89227f6e41' .
        '00d47d6ccb9c7d42fc43280ecc2ed386e81ff65bc5d6a2ae78db7372f5dc' .
        'f780f4558e7ed3dd0c96a1b40727ac56c5165aed700a3b63997893a1fb21' .
        '4e882221f0dd9604820dc34e2725dd6901c93e0ca56f6d76d495c332edc5' .
        'b81747c4c447a941f3';
$dsa = openssl_pkey_new(array(
    'dsa' => array(
        'p' => hex2bin($phex),
        'q' => hex2bin($qhex),
        'g' => hex2bin($ghex)
    )
));
$details = openssl_pkey_get_details($dsa);
$dsa_details = $details['dsa'];
openssl_pkey_test_cmp($phex, $dsa_details['p']);
openssl_pkey_test_cmp($qhex, $dsa_details['q']);
openssl_pkey_test_cmp($ghex, $dsa_details['g']);
var_dump(strlen($dsa_details['priv_key']));
var_dump(strlen($dsa_details['pub_key']));

// DH
$phex = 'dcf93a0b883972ec0e19989ac5a2ce310e1d37717e8d9571bb7623731866e61e' .
        'f75a2e27898b057f9891c2e27a639c3f29b60814581cd3b2ca3986d268370557' .
        '7d45c2e7e52dc81c7a171876e5cea74b1448bfdfaf18828efd2519f14e45e382' .
        '6634af1949e5b535cc829a483b8a76223e5d490a257f05bdff16f2fb22c583ab';

$dh_details = array('p' => $phex, 'g' => '2');
$dh = openssl_pkey_new(array(
    'dh'=> array('p' => hex2bin($phex), 'g' => '2'))
);
$details = openssl_pkey_get_details($dh);
$dh_details = $details['dh'];
openssl_pkey_test_cmp($phex, $dh_details['p']);
var_dump($dh_details['g']);
var_dump(strlen($dh_details['pub_key']));
var_dump(strlen($dh_details['priv_key']));

// EC - generate keypair with curve_name
$curve_name = 'prime256v1';
$ec = openssl_pkey_new(array(
    'ec'=> array('curve_name' => $curve_name))
);
$details = openssl_pkey_get_details($ec);
$ec_details = $details['ec'];
var_dump($curve_name === $ec_details['curve_name']);
var_dump(strlen($ec_details['x']));
var_dump(strlen($ec_details['y']));
var_dump(strlen($ec_details['d']));

// EC - generate keypair with custom params (SM2 curve)
$p = hex2bin('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF');
$a = hex2bin('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC');
$b = hex2bin('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93');
$order = hex2bin('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123');
$g_x = hex2bin('32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7');
$g_y = hex2bin('BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0');

$ec = openssl_pkey_new(array(
    'ec'=> array(
        'p' => $p,
        'a' => $a,
        'b' => $b,
        'order' => $order,
        'g_x' => $g_x,
        'g_y' => $g_y,
    )
));

$details = openssl_pkey_get_details($ec);
$ec_details = $details['ec'];
var_dump($ec_details['curve_name'] === 'SM2');
var_dump(strlen($ec_details['x']));
var_dump(strlen($ec_details['y']));
var_dump(strlen($ec_details['d']));

// EC - generate keypair from priv_key(d) with custom params (ECDSA curve)
$d = hex2bin('8D0AC65AAEA0D6B96254C65817D4A143A9E7A03876F1A37D');
$x = hex2bin('98E07AAD50C31F9189EBE6B8B5C70E5DEE59D7A8BC344CC6');
$y = hex2bin('6109D3D96E52D0867B9D05D72D07BE5876A3D973E0E96792');
$p = hex2bin('BDB6F4FE3E8B1D9E0DA8C0D46F4C318CEFE4AFE3B6B8551F');
$a = hex2bin('BB8E5E8FBC115E139FE6A814FE48AAA6F0ADA1AA5DF91985');
$b = hex2bin('1854BEBDC31B21B7AEFC80AB0ECD10D5B1B3308E6DBF11C1');
$g_x = hex2bin('4AD5F7048DE709AD51236DE65E4D4B482C836DC6E4106640');
$g_y = hex2bin('02BB3A02D4AAADACAE24817A4CA3A1B014B5270432DB27D2');
$order = hex2bin('BDB6F4FE3E8B1D9E0DA8C0D40FC962195DFAE76F56564677');

$ec = openssl_pkey_new(array(
    'ec'=> array(
        'p' => $p,
        'a' => $a,
        'b' => $b,
        'order' => $order,
        'g_x' => $g_x,
        'g_y' => $g_y,
        'd' => $d,
    )
));

$details = openssl_pkey_get_details($ec);
$ec_details = $details['ec'];
var_dump($ec_details['x'] === $x);
var_dump($ec_details['y'] === $y);
var_dump($ec_details['d'] === $d);

?>
--EXPECTF--
int(0)
int(0)
int(0)
int(0)
int(0)
int(0)
int(0)
int(0)

int(0)
int(0)
int(0)
int(%d)
int(%d)
int(0)
string(1) "2"
int(%d)
int(%d)
bool(true)
int(%d)
int(%d)
int(%d)
bool(true)
int(%d)
int(%d)
int(%d)
bool(true)
bool(true)
bool(true)
