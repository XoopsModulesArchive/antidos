<?php

function antidos_register_bad_ips($ip)
{
    $xoopsDB = XoopsDatabaseFactory::getDatabaseConnection();

    $rs = $xoopsDB->query('SELECT conf_value FROM ' . $xoopsDB->prefix('config') . " WHERE conf_name='bad_ips' AND conf_modid=0 AND conf_catid=1");

    [$bad_ips_serialized] = $xoopsDB->fetchRow($rs);

    $bad_ips = unserialize($bad_ips_serialized);

    $bad_ips[] = $ip;

    $conf_value = addslashes(serialize(array_unique($bad_ips)));

    $xoopsDB->queryF('UPDATE ' . $xoopsDB->prefix('config') . " SET conf_value='$conf_value' WHERE conf_name='bad_ips' AND conf_modid=0 AND conf_catid=1");
}

function b_antidos_show($options)
{
    global $HTTP_SERVER_VARS;

    $ip = $HTTP_SERVER_VARS['REMOTE_ADDR'];

    [$count_warn, $banip_flag, $banip_sec, $injection_banip_flag] = $options;

    $accessfile = XOOPS_ROOT_PATH . '/cache/antidos_access_log';

    $accesses = [];

    $die_flag = false;

    $stage = 0;

    $now = $expire = time();

    // Injection Check

    $bad_globals = ['xoopsDB', 'xoopsUser', 'xoopsUserIsAdmin', 'xoopsConfig', 'xoopsOption', 'xoopsModule', 'xoopsModuleConfig'];

    foreach ($bad_globals as $bad_global) {
        if (isset($_GET[$bad_global]) || isset($_POST[$bad_global]) || isset($_COOKIE[$bad_global])) {
            if ($injection_banip_flag) {
                antidos_register_bad_ips($ip);
            }

            exit;
        }
    }

    // DoS Check

    if (empty($ip) || '' == $ip) {
        return [];
    }

    // read from accessfile

    $fp = @fopen($accessfile, 'rb');

    if (false !== $fp) {
        $expire = (int)fgets($fp, 65536);

        $stage = (int)fgets($fp, 65536);

        $rsv2 = fgets($fp, 65536);

        $rsv3 = fgets($fp, 65536);

        if ($expire >= $now) {
            $accesses = unserialize(fgets($fp, 65536));

            if (!is_array($accesses)) {
                $accesses = [];
            }
        } else {
            $expire = $now;

            $stage = 0;
        }

        fclose($fp);
    }

    if (empty($accesses[$ip])) {
        $accesses[$ip] = 1;
    } else {
        $accesses[$ip]++;
    }

    //	error_log( $accesses[ $ip ] . ":$expire:$stage\n" , 3 , "/tmp/error_log" ) ;

    // DoS judgement

    if ($expire == $now) {
        // normal stage

        if ($accesses[$ip] >= $count_warn) {
            $die_flag = true;

            if ($banip_flag) {
                $expire = $now + $banip_sec;

                $stage = 1;
            }
        }
    } elseif ($stage > 0) {
        // 1st stage for protecting from DoS

        if ($accesses[$ip] >= $count_warn * $banip_sec) {
            // register bad_ips into XoopsConfig

            antidos_register_bad_ips($ip);

            $die_flag = true;

            $expire = $now;

            $stage = 0;
        }
    }

    // write into accessfile

    $fp = @fopen($accessfile, 'wb');

    @flock($fp, LOCK_EX);

    @fwrite($fp, $expire . "\n");

    @fwrite($fp, $stage . "\n\n\n");

    @fwrite($fp, serialize($accesses) . "\n");

    @flock($fp, LOCK_UN);

    @fclose($fp);

    if ($die_flag) {
        die(_MB_ANTIDOS_MES_DONTATTACK);
    }

    return [];
}

function b_antidos_edit($options)
{
    $register_banip_on = $options[1] ? 'checked' : '';

    $register_banip_off = $options[1] ? '' : 'checked';

    $injection_banip_on = $options[3] ? 'checked' : '';

    $injection_banip_off = $options[3] ? '' : 'checked';

    $form = '
		' . _MI_ANTIDOS_COUNT_WARN_PREFIX . " &nbsp;
			<input type='text' name='options[0]' value='{$options[0]}' size='2'>" . _MI_ANTIDOS_WORD_ACCESS . ' / ' . _SECOND . '&nbsp;' . _MI_ANTIDOS_COUNT_WARN_SUFFIX . '
			<br>
		' . _MI_ANTIDOS_QUERY_REGISTER_BAD_IPS . " &nbsp;
			<input type='radio' name='options[1]' value='1' $register_banip_on>" . _YES . "
			<input type='radio' name='options[1]' value='0' $register_banip_off>" . _NO . '
			<br>
		' . _MI_ANTIDOS_SECOND_REGISTER_PREFIX . " &nbsp;
			<input type='text' name='options[2]' value='{$options[2]}' size='2'>" . _MI_ANTIDOS_SECOND_REGISTER_SUFFIX . '
			<br>
		' . _MI_ANTIDOS_QUERY_INJECTION_BAD_IPS . " &nbsp;
			<input type='radio' name='options[3]' value='1' $injection_banip_on>" . _YES . "
			<input type='radio' name='options[3]' value='0' $injection_banip_off>" . _NO . "
			<br>
	\n";

    return $form;
}
