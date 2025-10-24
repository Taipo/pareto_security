<?php
class pareto_setup {
    const PARETO_VERSION     = '3.3.2';
    const CF_URL_IPV4        = 'https://www.cloudflare.com/ips-v4';
    const CF_URL_IPV6        = 'https://www.cloudflare.com/ips-v6';
    const QC_URL             = 'https://www.quic.cloud/ips';
    public $_open_basedir     = 0;
    public $_banip            = 0;
    public $_quietscript      = 0;
    public $_get_ip_count     = 0;
    public $_post_filter_mode = 0;
    public $_ban_time         = 86400; // 24 hours
    public $_hard_ban_count   = 10;
    public $_total_ips        = 500;
    public $_log_total        = 100;
    public $_doc_root;
    public $_datalist = array();
    public $_log_file;
    public $_log_file_key;
    public $_bypassbanip      = false;
    public $_spider_bypass    = false;
    public $_threshold        = 9;
    public $_hard_ban         = 12;
    public $_injectors        = array();
    public $_ip_array         = array();
    public $_get_all          = array();
    public $_post_all         = array();
    public $lockdown_setting  = 'pareto_security_lockdown';
    public $_hard_ban_mode    = false;
    public $_tor_block        = false;
    public $_disable_htaccess = 0;
    public $_timestamp        = '';
    public $settings_field    = 'pareto_security_settings_options';
    public $ip_hash_list      = 'pareto_security_ip_flood_list';
    public $_trim_log_entry   = 450;
    public $_time_offset;
    public $_adv_mode  = 0;
    public $_safe_host = '';
    public $_client_ip;
    public $_silent_mode     = 0;
    public static $default_settings = array(
        'advanced_mode'                  => 0,
        'ban_mode'                  => 0,
        'hard_ban_mode'                  => 0,
        'safe_list'                  => '',
        'email_report'                  => 0,
        'safe_list'                  => '',
        'admin_ip'                  => '',
        'tor_block'                  => 0,
        'disable_htaccess'                  => 0,
        'silent_mode'                  => 0,
        'server_ip'                  => ''
    );
    public $cf_ipv4_ranges   = array(
        '173.245.48.0/20',
        '103.21.244.0/22',
        '103.22.200.0/22',
        '103.31.4.0/22',
        '141.101.64.0/18',
        '108.162.192.0/18',
        '190.93.240.0/20',
        '188.114.96.0/20',
        '197.234.240.0/22',
        '198.41.128.0/17',
        '162.158.0.0/15',
        '104.16.0.0/13',
        '104.24.0.0/14',
        '172.64.0.0/13',
        '131.0.72.0/22'
    );
    public $cf_ipv6_ranges   = array(
        '2400:cb00::/32',
        '2606:4700::/32',
        '2803:f800::/32',
        '2405:b500::/32',
        '2405:8100::/32',
        '2a06:98c0::/29',
        '2c0f:f248::/32'
    );
    public $qc_ip_ranges     = array(
        '102.221.36.98',
        '102.221.36.99',
        '103.146.63.42',
        '103.152.118.219',
        '103.152.118.72',
        '103.164.203.163',
        '103.188.22.12',
        '103.28.90.190',
        '104.225.142.116',
        '104.244.77.37',
        '109.248.43.195',
        '135.148.120.32',
        '136.243.106.228',
        '139.59.21.152',
        '141.164.38.65',
        '144.202.115.5',
        '146.59.68.239',
        '146.88.239.197',
        '147.78.0.165',
        '147.78.3.13',
        '149.248.44.108',
        '152.228.171.66',
        '156.67.218.140',
        '157.90.154.114',
        '158.51.123.249',
        '162.254.117.80',
        '162.254.118.29',
        '163.182.174.161',
        '163.47.21.168',
        '164.52.202.100',
        '167.88.61.211',
        '170.249.218.98',
        '172.111.38.73',
        '178.17.171.177',
        '178.22.124.247',
        '178.22.124.251',
        '178.255.220.12',
        '18.192.146.200',
        '185.116.60.231',
        '185.116.60.232',
        '185.126.237.129',
        '185.126.237.143',
        '185.205.187.233',
        '185.228.26.40',
        '185.53.57.40',
        '185.53.57.89',
        '188.172.228.182',
        '188.172.229.113',
        '188.64.184.71',
        '190.92.176.5',
        '191.96.101.140',
        '192.99.38.117',
        '193.203.191.189',
        '194.163.134.104',
        '194.36.144.221',
        '195.231.17.141',
        '198.38.89.73',
        '199.59.247.242',
        '200.58.127.145',
        '201.182.97.70',
        '202.182.123.93',
        '202.61.226.253',
        '204.10.163.237',
        '207.246.89.164',
        '209.124.84.191',
        '209.208.26.218',
        '211.23.143.87',
        '213.159.1.75',
        '213.183.48.170',
        '213.184.85.245',
        '213.59.121.226',
        '216.238.106.164',
        '216.238.71.13',
        '216.250.96.181',
        '23.150.248.180',
        '27.131.75.40',
        '27.131.75.41',
        '3.109.250.83',
        '3.6.218.117',
        '31.131.4.244',
        '31.22.115.186',
        '34.247.229.180',
        '37.120.131.40',
        '38.101.149.196',
        '38.54.30.31',
        '38.54.42.189',
        '38.54.79.187',
        '38.60.253.237',
        '41.185.29.210',
        '41.223.52.170',
        '43.231.0.46',
        '45.124.65.86',
        '45.132.244.92',
        '45.248.77.61',
        '45.32.169.55',
        '45.32.210.159',
        '45.77.233.177',
        '45.77.43.177',
        '45.77.57.25',
        '46.250.220.133',
        '49.12.102.29',
        '5.134.119.103',
        '5.134.119.194',
        '5.188.183.13',
        '5.189.146.228',
        '51.79.221.227',
        '51.81.186.219',
        '51.81.33.156',
        '54.162.162.165',
        '54.36.103.97',
        '61.219.247.87',
        '61.219.247.90',
        '63.251.96.112',
        '64.176.4.251',
        '64.227.16.93',
        '65.20.75.178',
        '65.21.81.50',
        '65.21.81.51',
        '66.42.116.188',
        '69.50.95.216',
        '70.34.205.229',
        '79.172.239.249',
        '81.31.156.245',
        '81.31.156.246',
        '83.229.71.151',
        '86.105.14.231',
        '86.105.14.232',
        '89.58.38.4',
        '91.201.67.57',
        '91.228.7.67',
        '93.95.227.66',
        '94.75.232.90',
        '95.179.133.28',
        '95.216.116.209'
    );
    public $ps_icon          = "data:image/png;base64,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";
    public $pagehook;
    public $page_id;
    public $options = array();
    public $logs;
    public $time_zone;
    public $_textdomain = 'pareto_security_settings';
    public $_ban_mode   = 0;
    public $lockdown_status;
    public $prefix = 'pareto_settings';
    public function __construct() {
        return;
    }
}
