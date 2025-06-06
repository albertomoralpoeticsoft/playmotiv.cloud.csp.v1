<?php

/**
 *
 * Plugin Name: playmotiv-cloud-csp-v1
 * Plugin URI: http://playmotiv.cloud/plugins/playmotiv-cloud-csp-v1
 * Description: Playmotiv Cloud Plugin - CSP V1
 * Version: 0.00
 * Author: Bracnoria Team
 * Author URI: http://playmotiv.cloud/team
 */
 
defined('ABSPATH') || exit;

function csp_nonce_generate() {

  $nonce = esc_attr(base64_encode(random_bytes(16)));

  return $nonce;
}

function csp_should_run() {

  if (
    defined('DOING_AJAX') && DOING_AJAX 
    ||
    defined('REST_REQUEST') && REST_REQUEST
  ) {
    
    return false;
  }
  
  if (!headers_sent()) {

    $accept = $_SERVER['HTTP_ACCEPT'] ?? '';

    if (stripos($accept, 'text/html') === false) {

      return false;
    }
  }

  return true;
}

function csp_nonce_set_header() { 

  if (!csp_should_run()) return;

  global $csp_nonce;
  $csp_nonce = csp_nonce_generate();

  header("Content-Security-Policy: script-src 'self' 'nonce-$csp_nonce'; style-src 'self' 'nonce-$csp_nonce';");
}

function csp_nonce_inject_into_tags($buffer) {

  global $csp_nonce;

  $buffer = preg_replace_callback(
    '/<script(?![^>]*nonce)([^>]*)>/i',
    fn($m) => '<script nonce="' . $csp_nonce . '"' . $m[1] . '>',
    $buffer
  );

  $buffer = preg_replace_callback(
    '/<style(?![^>]*nonce)([^>]*)>/i',
    fn($m) => '<style nonce="' . $csp_nonce . '"' . $m[1] . '>',
    $buffer
  );

  $buffer = preg_replace_callback(
     '/<div\s+id=["\']PrivacityText["\']\s+style=["\']display\s*:\s*none\s*;?["\']\s*><\/div>/i',
      fn($m) => '',
      $buffer
  );

  return $buffer;
}

add_action(
  'send_headers', 
  'csp_nonce_set_header'
);

add_action(
  'login_init', 
  function () {

    if(csp_should_run()) {

      ob_start('csp_nonce_inject_into_tags');
      csp_nonce_set_header();
    }
  }
);

add_action(
  'template_redirect', 
  function () {

    if (csp_should_run()) {
      
      ob_start('csp_nonce_inject_into_tags');
    }
  }
);

add_action(
  'init', 
  function () {

    if (csp_should_run()) {

      ob_start('csp_nonce_inject_into_tags');
    }
  }, 
  1
);

function disable_wp_a11y_script() {

  wp_deregister_script('wp-a11y');
}
add_action('login_enqueue_scripts', 'disable_wp_a11y_script');
add_action('admin_enqueue_scripts', 'disable_wp_a11y_script');