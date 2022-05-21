<?php  // Moodle configuration file

unset($CFG);
global $CFG;
$CFG = new stdClass();

$CFG->dbtype    = 'mysqli';
$CFG->dblibrary = 'native';
$CFG->dbhost    = 'localhost';
$CFG->dbname    = 'activedirectory';
$CFG->dbuser    = 'root';
$CFG->dbpass    = 'Sp0rt3l4#91';
$CFG->prefix    = 'ad_';
$CFG->dboptions = array (
  'dbpersist' => 0,
  'dbport' => '',
  'dbsocket' => '',
  'dbcollation' => 'utf8mb4_unicode_ci',
);

$CFG->wwwroot   = 'https://activedirectory.test';
$CFG->dataroot  = '/var/www/moodledataad';
$CFG->admin     = 'admin';

$CFG->directorypermissions = 0777;
@error_reporting(E_ALL | E_STRICT); 
    @ini_set('display_errors', '1'); 
    $CFG->debug = (E_ALL | E_STRICT); 
    $CFG->debugdisplay = 1;
require_once(__DIR__ . '/lib/setup.php');

// There is no php closing tag in this file,
// it is intentional because it prevents trailing whitespace problems!
