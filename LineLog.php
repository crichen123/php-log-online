<?php
//session_start(); // 开启session功能
/*
 * PHP在线通用日志浏览
 *      1. 单文件绿色版,部署超简单
 *      2. 支持目录树形层级结构显示，支持目录展开或收起
 *      3. 支持日志文件下载、文件删除、文件查看、目录清空功能
 *      4. 支持用户登录验证、IP验证等多种权限验证功能
 *      5. 修改$authconfig配置信息使用
 * @since 0.1 新增子目录内容视图功能，跳转限定在子目录中；新增清空目录功能
 * @since 0.2 重构代码格式，纯PHP代码改为HTML混合代码，英文按钮改为中文按钮
 * @since 0.3 fn_tail方法改为直接输出,解决大文件读取显示空白的问题
 * @since 0.4 为适应负载均衡多台服务器分布式使用场景,登录会话保持由单机的session存储改为url参数token
 */

define('VERSION', '0.4.0');
// 程序名称
define('APPNAME', 'LineLog');
// 日志根目录
define('ROOTPATH', '../logs/');

// 超时时间 (1 hours, 1 minutes, 30 seconds)
JWTLite::$TOKEN_EXP = '1 hours';
// 允许运行的服务器列表(适用于分布式环境）
JWTLite::$TOKEN_AUD = '127.0.0.1,51.66.99.15';
// 签名密钥
JWTLite::$TOKEN_KEY = 'U63rxInZ7!';
//自动延期时长, 每次页面跳转操作会重新生成一个延期过的TOKEN,类似session的效果,只要一直操作就一直不会过期
JWTLite::$TOKEN_REFRESH_SECOND = 1800;

/**
 * 页面访问验证配置
 */
JWTLite::$AUTH_CONFIG = [
    'admins' => ['admin' => 'passWd123', 'testuser' => 'passWd123'], // 允许登录的帐号列表
    'ips' => ['127.0.0.1', '110.52.27.168'], // 允许访问的ip地址列表
    'current_authtype' => 1, // 指定页面访问验证类型：0:无需验证;1:帐号密码验证;2:IP验证;3:混合验证(先IP验证,IP验证失败则转入帐号密码验证)
];

// 页面访问验证配置
JWTLite::check_login();
list($loginid, $token, $loginexp) = array_values(JWTLite::$LOGIN_RESULT);

$path = input('path'); // 路径
$dirpath = input('dirpath'); // 目录路径
$action = input('action'); // 操作
if (input('debugmsg')) {
    debugmsg('logadminlite.php[0]', 'debugtest');
}

if ($path) {
    if (!file_exists($path)) {
        exit('路径 [' . $path . '] 不存在! <a href="?path' . ROOTPATH . '&token=' . $token . '">[返回]</a>');
    }
    if ($action == "delete" || $action == "clear") {
        try {
            if (is_dir($path)) {
                fn_rmdir($path, 'delete' == $action);
            } else {
                unlink($path);
            }
        } catch (Exception $ex) {
            echo $ex->getMessage();
        }
        echo 'delete' == $action ? '删除成功!' : '清空成功!';
        if ($dirpath) {
            header('location:?path=' . $dirpath . '&dirpath=' . $dirpath . '&token=' . $token);
        } else {
            header('location:?path=' . ROOTPATH . '&token=' . $token);
        }
        exit;
    }
}
?>
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <title><?php echo ($path ? short_text(basename($path), 16, true) . ' - ' : ''), APPNAME, ' - ', VERSION ?></title>
        <style type="text/css">
            body{font-size:13px;}
            a{text-decoration:none}
            h1 a { color:#555; font-weight: normal;}
            .aside{width:240px;max-height:600px;overflow:auto;float:left;font-size:13px}
            .main{width:800px;float:left;margin-left:10px;}
            ul{margin:0}li{list-style:none;margin-left:-40px;}
            li.active { color:#F00;}
            li.active a{ color:#F00;}
            text{color:#333;}
        </style>
    </head>
    <body>
        <script src="http://apps.bdimg.com/libs/jquery/2.1.4/jquery.min.js"></script>
        <?php
        echo '<h1>', APPNAME, ' ';
        echo '<a href="?token=', $token, '" title="新开一个页面" target="_blank" style="font-size:12px;">[新窗口]</a>';
        echo '<a href="#" title="刷新当前页面" style="font-size:12px;" onclick="location.reload()">[刷新]</a>';
        echo '</h1>';
        if (isset($loginid)) {
            echo '<span title="登录过期时间：', $loginexp, ' (超时前进行跳转操作能让登录会话自动延期,避免重登录操作~)">', $loginid, '</span>';
            echo ' [<a href="?action=logout" onclick="return confirm(\'您确定要注销登录吗?\');">注销登录</a>]';
        }
        echo ' 客户端IP:', $_SERVER['REMOTE_ADDR'], ' <span style="display:none">服务器IP:' . JWTLite::get_host_ip() . '</span> <a href="#" id="lnk-toggle-ipinfo">[...]</a>';

        echo '<div><a href="?path=', ROOTPATH, '&token=', $token, '">[根目录]</a></div>';
        if ($path) {
            if ($dirpath) { // 限定在子目录中
                echo '<div style="margin:3px 0; color:#666">当前路径：', $dirpath;
                echo ' [<a title="refresh,刷新" href="?path=' . $dirpath . '&dirpath=', $dirpath, '&token=', $token, '">刷新</a>]';
                echo '[<a title="clear,清空目录" href="?path=' . $dirpath . '&dirpath=' . $dirpath . '&token=', $token, '&action=clear" onclick="return confirm(\'您确定要清空当前目录吗?\')">清空</a>]';
                echo '[<a title="delete,删除目录" href="?path=' . $dirpath . '&dirpath=' . $dirpath . '&token=', $token, '&action=delete" onclick="return confirm(\'您确定要删除当前目录吗?\')">删除</a>]';
                echo '</div>';
            } else { // 限定在根目录中
                echo '<div style="margin:3px 0; color:#666">当前路径：', $path;
                echo ' [<a title="refresh,刷新" href="?path=' . $path . '&token=', $token, '">刷新</a>]';
                if (is_file($path)) {
                    echo '[<a title="download [右键点击下载]" href="' . $path . '&token=', $token, '">&darr;</a>]';
                }
                if (is_dir($path)) {
                    echo '[<a title="clear,清空目录" href="?path=' . $path . '&dirpath=' . $path . '&token=', $token, '&action=clear" onclick="return confirm(\'您确定要清空当前目录吗?\')">清空</a>]';
                    echo '[<a title="delete,删除目录" href="?path=' . $path . '&dirpath=' . $path . '&token=', $token, '&action=delete" onclick="return confirm(\'您确定要删除当前目录吗?\')">删除</a>]';
                }
                echo '</div>';
            }
        }
        ?>
        <div class="aside">
            <?php
            echo '<ul>';
            if ($dirpath) {
                fn_scandir($dirpath, 0, true, $path, $dirpath, $token);
            } else {
                fn_scandir(($path && is_dir($path) ? $path : ROOTPATH), 0, true, $path, $dirpath, $token);
            }
            echo '</ul>';
            ?>
        </div>
        <div class="main">
            <?php
            if ($path && is_file($path)) {
                echo '<div style="color:#666">size:', format_bytes(filesize($path)), ', modified time:', date('Y-m-d H:i:s', filectime($path)), ', readable:', is_readable($path), ', writeable:', is_writable($path), ', executable:', is_executable($path), '</div>';
                echo '<textarea cols="150" rows="40">';
                fn_tail($path);
                echo '</textarea>';
            }
            ?>
        </div>
        <div style="clear:both"></div>
        <script>
            $('#lnk-toggle-ipinfo').click(function () {
                var $a = $(this);
                if ($a.text() == '[...]') {
                    $a.text('[x]').prev().show();
                } else {
                    $a.text('[...]').prev().hide();
                }
                return false;
            })
            $(".btn_switch").click(function () {
                var $this = $(this);
                if ($this.text() == "[-]") {
                    $this.text("[+]").attr("title", "展开");
                    $this.parent().children("ul").hide();
                } else {
                    $this.text("[-]").attr("title", "收起");
                    $this.parent().children("ul").show();
                }
            });
        </script>
    </body>
</html>
<?php
/**
 * 调试消息
 * @param string $location
 * @param string $msg
 * @param boolean $enable
 * @param boolean $json
 * @return type
 */
function debugmsg($location, $msg, $enableOrOption = true, $to_josn = false, $msg_type = 'debug') {
    // 参数判断
    if (is_array($enableOrOption)) {
        $defaultOption = array(
            'enable' => true, 
            'to_json' => false, 
            'msg_type' => 'debug', 
        );
        $defaultOption = array_merge($defaultOption, $enableOrOption);
        list($enable, $to_josn, $msg_type) = array_values($defaultOption);
    } else {
        $enable = $enableOrOption;
    }
    // 白名单和黑名单
    if (!$enable) {
        $whites = array();
        if ($whites) {
            foreach ($whites as $white) {
                if (false !== strpos($location, $white)) {
                    $enable = true;
                    break;
                }
            }
        }
    } else {
        $blacks = array('bm/index.action.php', 'xiacai.action.php', 'rank.action.php', 'user.php', 'setting.action.php', 'user.action.php', 'app.action.php', 'gamesModel.class.php');
        if ($blacks) {
            foreach ($blacks as $black) {
                if (false !== strpos($location, $black)) {
                    $enable = false;
                    false;
                }
            }
        }
    }
    if (!$enable) {
        return; 
    }
    if (!is_string($msg)) {
        if (is_array($msg) && $to_josn) {
            $msg = json_encode($msg);
        } else {
            $msg = var_export($msg, true);
        }
    }
    if ($msg_type == 'show') {
        echo date('Y-m-d H:i:s'), ' ', $location, '<br />', PHP_EOL, $msg, '<hr />', PHP_EOL;
    }
    $standaloneLocations = array('ylcpsapi.action.php' => 'ylcpsapi', 'ylsoaapi.action.php' => 'ylsoaapi', 'video.action.php' => 'video');
    $filename = 'log';
    foreach ($standaloneLocations as $standaloneLocation => $aliasFile) {
        if (false !== strpos($location, $standaloneLocation)) {
            $filename = $aliasFile;
        }
    }
    $standaloneTypes = array('error');
    if ($msg_type && in_array($msg_type, $standaloneTypes)) {
        $filename .= '-' . $msg_type;
    }
    $content = date('Y-m-d H:i:s') . PHP_EOL . $location . PHP_EOL . $msg . PHP_EOL . PHP_EOL;
    $dir = APP_ROOT_PATH . 'java/logs/debug/';
    if (!is_dir($dir)) {
        mkdir($dir);
    }
    $path = $dir . $filename . '-' . date('mdH') . '.txt';
    if (file_exists($path) && (filesize($path) > 2097152)) { 
        $path = $dir . $filename . '-' . date('mdHi') . '.txt';
    }
    if ($fp = fopen($filepath, 'a')) {
        $startTime = microtime();
        do {
            $canWrite = flock($fp, LOCK_EX);
            if (!$canWrite) {
                usleep(round(rand(0, 100) * 1000));
            }
        } while ((!$canWrite) && ((microtime() - $startTime) < 1000));
        if ($canWrite) {
            fwrite($fp, $content);
        }
        fclose($fp);
    }
}

/**
 * PHP高效遍历文件夹（大量文件不会卡死）
 */
function fn_scandir($path = './', $level = 0, $showfile = true, $curpath = '', $dirpath = '', $token = '') {
    if (!file_exists($path)) {
        echo '路径[', $path, ']不存在';
        return;
    }
    $file = new FilesystemIterator($path);
    $filename = '';
    $url = '';
    $prefix = ''; // 树形层级图形
    $isactive = ''; 
    foreach ($file as $fileinfo) {
        $filename = $fileinfo->getFilename();
        $filepath = $path . $filename;
        $isactive = ($curpath == $filepath ? ' class="active"' : '');
        $prefix = $level > 0 ? ('|' . str_repeat('--', $level)) : '';
        if ($fileinfo->isDir()) {
            $filepath = $filepath . '/';
            $url = '<a title="' . $filepath . '" href="?path=' . $filepath . '&dirpath=' . $filepath . '&token=' . $token . '">' . short_text($filename, 12) . '</a>';
            $url .= '<span style="font-weight:normal">[<a title="新窗口打开目录 ' . $filepath . '" href="?path=' . $filepath . '&dirpath=' . $dirpath . '&token=' . $token . '" target="_blank">新</a>]';
            $url .= '[<a title="刷新目录" href="?path=' . ($dirpath ? $dirpath : ROOTPATH) . '&dirpath=' . $dirpath . '&token=' . $token . '">刷</a>]';
            $url .= '[<a title="清空目录" href="?path=' . $filepath . '&dirpath=' . $dirpath . '&token=' . $token . '&action=clear" onclick="return confirm(\'您确定要清空当前目录吗?\')">清</a>]';
            $url .= '[<a title="删除目录" href="?path=' . $filepath . '&dirpath=' . $dirpath . '&token=' . $token . '&action=delete" onclick="return confirm(\'您确定要删除当前目录吗?\')">删</a>]</span>';
            echo '<li', $isactive, '><strong>' . $prefix . $url . '/</strong> <a href="#" class="btn_switch" title="收起">[-]</a>' . PHP_EOL;
            echo '<ul>';
            fn_scandir($filepath, $level + 1, $showfile, $curpath, $dirpath, $token);
            echo '</ul>';
            echo '</li>';
        } else {
            if ($showfile) {
                $url = '<a title="' . $filepath . '" href="?path=' . $filepath . '&dirpath=' . $dirpath . '&token=' . $token . '">' . short_text($filename, 12) . '</a> [<a title="新窗口打开文件 ' . $filepath . '" href="?path=' . $filepath . '&dirpath=' . $dirpath . '&token=' . $token . '" target="_blank">新</a>][<a title="删除文件" href="?path=' . $filepath . '&dirpath=' . $dirpath . '&token=' . $token . '&action=delete" onclick="return confirm(\'您确定要删除吗?\')">删</a>][<a title="[右键点击下载]" href="' . $filepath . '" target="_blank">下</a>]';
                echo '<li', $isactive, '>' . $prefix . $url . '</li>' . PHP_EOL;
            }
        }
        /*
          if ($fileinfo->isDir()) {
          fn_scandir($filepath, $level + 1);
          } */
    }
}

/**
 * 格式化文件字节大小
 */
function format_bytes($size) {
    $units = array(' B', ' KB', ' MB', ' GB', ' TB');
    for ($i = 0; $size >= 1024 && $i < 4; $i++)
        $size /= 1024;
    return round($size, 2) . $units[$i];
}

/**
 * 删除非空目录里面所有文件和子目录
 */
function fn_rmdir($dir, $delSelf = true) {
    $dh = opendir($dir);
    while ($file = readdir($dh)) {
        if ($file != "." && $file != "..") {
            $fullpath = $dir . "/" . $file;
            if (is_dir($fullpath)) {
                fn_rmdir($fullpath, true);
            } else {
                unlink($fullpath);
            }
        }
    }
    closedir($dh);
    if (!$delSelf || rmdir($dir)) {
        return true;
    } else {
        return false;
    }
}

/**
 * PHP高效读取文件
 */
function fn_tail($filepath) {
    if (file_exists($filepath)) {
        if (false !== ($fp = fopen($filepath, "r"))) {
            $buffer = 1024; //每次读取 1024 字节
            while (!feof($fp)) {
                echo htmlspecialchars(fread($fp, $buffer));
            }
            fclose($fp);
        } else {
            echo 'file can not open! [' . $filepath . ']';
        }
    } else {
        echo 'file not exists! [' . $filepath . ']';
    }
}

/**
 * PHP高效写入文件（支持并发）
 */
function fn_write($filepath, $content) {
    if ($fp = fopen($filepath, 'a')) {
        $startTime = microtime();
        do {
            $canWrite = flock($fp, LOCK_EX);
            if (!$canWrite) {
                usleep(round(rand(0, 100) * 1000));
            }
        } while ((!$canWrite) && ((microtime() - $startTime) < 1000));
        if ($canWrite) {
            fwrite($fp, $content);
        }
        fclose($fp);
    }
}

/**
 * 获取用户输入
 */
function input($name, $defv = '', $filter = true) {
    if (isset($_REQUEST[$name])) {
        return $filter ? htmlspecialchars($_REQUEST[$name]) : $_REQUEST[$name];
    }
    return $defv;
}

/**
 * 截短字符串
 */
function short_text($str, $length, $behind = false) {
    $len = strlen($str);
    if ($len <= $length) {
        return $str;
    }
    return $behind ? '...' . substr($str, $len - $length) : substr($str, 0, $length) . '...';
}

/**
 * 用户登录认证类
 */
class JWTLite {

    /**
     *  超时时间 (1 hours, 1 minutes, 30 seconds)
     */
    public static $TOKEN_EXP = '1 hours';

    /**
     *  允许运行的服务器列表(适用于分布式环境,如果是负载均衡+高防IP环境,则填入高防IP即可),多个之间以逗号隔开,中间不要有空格
     */
    public static $TOKEN_AUD = '127.0.0.1,47.95.44.177,47.94.100.12,47.93.45.33,47.93.42.85';

    /**
     * 签名密钥
     */
    public static $TOKEN_KEY = 'InZ7!';

    /**
     * 自动延期时长, 每次页面跳转操作会重新生成一个延期过的TOKEN,类似session的效果,只要一直操作就一直不会过期
     */
    public static $TOKEN_REFRESH_SECOND = 1800;

    /**
     * 页面访问验证配置
     */
    public static $AUTH_CONFIG = array();

    /**
     * 登录结果
     */
    public static $LOGIN_RESULT = array();

    /**
     * 生成签名
     */
    public static function gen_sign(array $data = array()) {
        $tokenInfo = array(
            "exp" => strtotime("30 minutes"), // 默认TOKEN有效期30分钟
            "aud" => self::$TOKEN_AUD,
        );
        $data = array_merge($tokenInfo, $data);
        ksort($data);
        $md5Str = md5(self::$TOKEN_KEY . json_encode($data));
        $data['sign'] = substr($md5Str, 20, 6);
        unset($data['aud']);
        return $data;
    }

    /**
     * 验证签名
     */
    public static function check_sign($data) {
        if (empty($data['exp']) || empty($data['sign'])) {
            return array('status' => false, 'info' => '签名内容不规范');
        }
        $exp = $data['exp'];
        if ($exp < time()) {
            return array('status' => false, 'info' => '签名已过期');
        }
        if (self::$TOKEN_AUD) {
            $audArr = explode(',', self::$TOKEN_AUD);
            $hostIp = self::get_host_ip();
            if (!in_array($hostIp, $audArr)) {
                return array('status' => false, 'info' => '服务器不在白名单<span style="display:none">' . $hostIp . '</span>');
            }
        }
        $postSign = $data['sign'];
        unset($data['sign']);
        $data['aud'] = self::$TOKEN_AUD;
        ksort($data); // aud,exp,user
        $localSign = substr(md5(self::$TOKEN_KEY . json_encode($data)), 20, 6);
        if ($localSign != $postSign) {
            return array('status' => false, 'info' => '签名非法');
        }
        return array('status' => true, 'info' => '');
    }

    /**
     * 获取表单令牌
     */
    public static function get_token($data) {
        return base64_encode(json_encode(self::gen_sign($data)));
    }

    /**
     * 解析token
     */
    public static function parse_token($post_token = '') {
        if (!$post_token) {
            $post_token = htmlspecialchars(trim(input('token')));
        }
        if (!$post_token) {
            return ['status' => false, 'info' => 'TOKEN为空'];
        }
        $json = base64_decode($post_token);
        if (false === $json) {
            return ['status' => false, 'info' => 'TOKEN内容无效'];
        }
        $post = json_decode($json, true);
        if (!$post) {
            return ['status' => false, 'info' => 'TOKEN格式错误'];
        }
        $sigResult = self::check_sign($post);
        if (!$sigResult['status']) {
            return $sigResult;
        }
        return ['status' => true, 'info' => $post];
    }

    /**
     * 生成新的延期过的token
     */
    public static function refresh_token($exp, $token) {
        $tokenInfo = self::parse_token($token);
        $data = $tokenInfo['info'];
        unset($data['sign']);
        $data['exp'] = strtotime(self::$TOKEN_EXP) + self::$TOKEN_REFRESH_SECOND;
        return self::get_token($data);
    }

    /**
     * 用户登录操作
     */
    public static function dologin($admins, $urlparams = array()) {
        $posttoken = htmlspecialchars(input('login_token'));
        if ($posttoken) {
            $tokenInfo = self::parse_token($posttoken);
            $goback_btn = '<a href="?login">[返回]</a>';
            if (!$tokenInfo['status']) {
                exit($tokenInfo['info'] . $goback_btn);
            }
            $loginid = strval(htmlspecialchars(input('user')));
            $loginpwd = htmlspecialchars(input('pass'));
            if (!$loginid || !$loginpwd) {
                exit('表单填写不完整!' . $goback_btn);
            }
            if (!array_key_exists($loginid, $admins)) {
                exit('帐号不存在!' . $goback_btn);
            }
            if ($loginpwd != $admins[$loginid]) {
                exit('密码错误!' . $goback_btn);
            }
            $url = '?token=' . self::get_token(array('exp' => strtotime(self::$TOKEN_EXP), 'user' => $loginid));
            if ($urlparams) {
                $url .= '&' . http_build_query($urlparams);
            }
            header('location:' . $url);
        } else {
            echo '<form method="post" action="?action=login">';
            echo '<input type="text" name="user" placeholder="用户名" required="required" />';
            echo '<input type="password" name="pass" placeholder="密码" required="required" />';
            echo '<input type="hidden" name="login_token" value="', self::get_token(array('exp' => strtotime('3 minutes'), 'action' => 'login')), '" />';
            if ($urlparams) {
                foreach ($urlparams as $key => $val) {
                    echo '<input type="hidden" name="', $key, '" value="', $val, '" />';
                }
            }
            echo '<button type="submit">登录</button><button type="reset">重置</button> ';
            echo $_SERVER['REMOTE_ADDR'];
            echo '</form>';
        }
    }

    /**
     * 访问权限验证
     */
    public static function check_login($urlparams = array()) {
        $curAuthtypeId = self::$AUTH_CONFIG['current_authtype'];
        $curAuthStatus = true; 
        if ($curAuthtypeId == 2 || $curAuthtypeId == 3) { 
            $http_host = $_SERVER['REMOTE_ADDR'];
            if (!in_array($http_host, self::$AUTH_CONFIG['ips'])) {
                $curAuthStatus = false; 
                if ($curAuthtypeId == 2) {
                    exit('IP [' . $http_host . '] 禁止访问!');
                }
            }
        }

        $loginid = false; 
        $loginexp = ''; 
        $token = htmlspecialchars(trim(input('token'))); 
        if ($curAuthtypeId == 1 || ($curAuthtypeId == 3 && !$curAuthStatus)) { 
            if ($token) { 
                $tokenInfo = self::parse_token($token);
                if ($tokenInfo['status']) {
                    $loginid = $tokenInfo['info']['user'];
                    $loginexp = date('Y-m-d H:i:s', $tokenInfo['info']['exp']);
                    if (self::$TOKEN_REFRESH_SECOND > 0) {
                        $refreshToken = self::refresh_token(self::$TOKEN_REFRESH_SECOND, $token);
                        $token = $refreshToken;
                    }
                } else {
                    echo '<div style="font-size:12px; color:#F00">', $tokenInfo['info'], '</div>';
                }
            }
            if (input('action') == 'logout') {
                header('location:?logout-success');
                exit;
            }
            if (!$loginid) {
                self::dologin(self::$AUTH_CONFIG['admins'], $urlparams);
                exit;
            }
        }
        self::$LOGIN_RESULT = compact('loginid', 'token', 'loginexp');
    }

    /**
     * 返回服务器IP
     */
    public static function get_host_ip() {
        return gethostbyname($_SERVER['SERVER_NAME']);
    }

}
