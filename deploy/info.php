<?php

/////////////////////////////////////////////////////////////////////////////
// General information
/////////////////////////////////////////////////////////////////////////////

$app['basename'] = 'mail_filter';
$app['version'] = '2.0.0';
$app['release'] = '1';
$app['vendor'] = 'ClearFoundation';
$app['packager'] = 'ClearFoundation';
$app['license'] = 'GPLv3';
$app['license_core'] = 'LGPLv3';
$app['description'] = lang('mail_filter_app_description');

/////////////////////////////////////////////////////////////////////////////
// App name and categories
/////////////////////////////////////////////////////////////////////////////

$app['name'] = lang('mail_filter_app_name');
$app['category'] = lang('base_category_server');
$app['subcategory'] = lang('base_subcategory_mail');
$app['menu_enabled'] = FALSE;

/////////////////////////////////////////////////////////////////////////////
// Packaging
/////////////////////////////////////////////////////////////////////////////

$app['core_only'] =  TRUE;

$app['core_requires'] = array(
    'app-base-core >= 1:1.6.5',
    'app-events-core',
    'app-mail-routing-core',
    'app-network-core',
    'app-smtp-core >= 1:1.5.40',
    'amavisd-new >= 2.6.5',
);

$app['core_directory_manifest'] = array(
    '/var/clearos/mail_filter' => array(),
    '/var/clearos/mail_filter/backup' => array(),
);

$app['core_file_manifest'] = array(
    'amavisd.php' => array('target' => '/var/clearos/base/daemon/amavisd.php'),
    'api.conf' => array(
        'target' => '/etc/amavisd/api.conf',
        'mode' => '0644',
        'config' => TRUE,
        'config_params' => 'noreplace',
    ),
    'smtp-event'=> array(
        'target' => '/var/clearos/events/smtp/mail_filter',
        'mode' => '0755'
    ),
);
