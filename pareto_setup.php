<?php
class pareto_setup {
    const   PARETO_VERSION = '2.9.1';
    const   CF_URL = 'https://www.cloudflare.com/ips-v4';
    const   QC_URL = 'https://www.quic.cloud/ips';
    public  $_open_basedir = 0;
    public  $_banip = 0;
    public  $_quietscript = 0;
    public  $_get_ip_count = 0;
    public  $_post_filter_mode = 0;
    public  $_ban_time = 86400; // 24 hours
    public  $_hard_ban_count = 10;
    public  $_total_ips = 500;
    public  $_log_total = 100;
    public  $_doc_root;
    public  $_datalist;
    public  $_log_file;
    public  $_log_file_key;
    public  $_bypassbanip = false;
    public  $_spider_bypass = false;
    public  $_threshold = 9;
    public  $_hard_ban = 12;
    public  $_injectors = array();
    public  $_ip_array = array();
    public  $_get_all = array();
    public  $_post_all = array();
    public  $lockdown_setting = 'pareto_security_lockdown';
    public  $_hard_ban_mode = false;
    public  $_tor_block = false;
    public  $_timestamp = '';
    public  $settings_field = 'pareto_security_settings_options';
    public  $ip_hash_list = 'pareto_security_ip_flood_list';
    public  $_trim_log_entry = 450;
    public  $_time_offset;
    public  $_adv_mode = 0;
    public  $_safe_host = '';
    public  $_client_ip;
    public static $default_settings = array( 'advanced_mode' => 0, 'ban_mode' => 0, 'hard_ban_mode' => 0, 'safe_list' => '', 'email_report' => 0, 'safe_list' => '', 'admin_ip' => '', 'tor_block' => 0, 'server_ip' => '' );
    public  $pagehook;
    public  $page_id;
    public  $options = array();
    public  $logs;
    public  $time_zone;
    public  $_textdomain = 'pareto_security_settings';
    public  $_ban_mode = 0;
    public  $lockdown_status;
    public  $prefix = 'pareto_settings';
    public function __construct() {
        return;
    }
}
