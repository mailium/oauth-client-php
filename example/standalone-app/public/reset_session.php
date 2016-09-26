<?php

session_start();

print "<h3>Session Before Reset:</h3>";
print "<pre>";
print_r($_SESSION);
print "</pre>";
print "<hr>";

// Reset all session keys

foreach ($_SESSION as $key => $value) {
    unset($_SESSION[$key]);
}

print "<h3>Session After Reset:</h3>";
print "<pre>";
print_r($_SESSION);
print "</pre>";
print "<hr>";