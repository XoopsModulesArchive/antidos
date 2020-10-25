<?php

function xoops_module_install_antidos($module)
{
    $xoopsDB = XoopsDatabaseFactory::getDatabaseConnection();

    $xoopsDB->queryF('UPDATE ' . $xoopsDB->prefix('config') . " SET conf_value=1 WHERE conf_name='enable_badips' AND conf_modid=0 AND conf_catid=1");
}
