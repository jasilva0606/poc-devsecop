<?php
require __DIR__ . '/../vendor/autoload.php';

// 1. Sanitizar el input (Evita XSS)
$city = isset($_GET['city']) ? htmlspecialchars($_GET['city'], ENT_QUOTES, 'UTF-8') : 'Buenos Aires';

// 2. Simulación de API (Quitamos shell_exec para evitar RCE)
// En lugar de ejecutar un comando de sistema, usamos lógica de PHP
$temp = rand(15, 30); 

echo "<h1>Weather Service</h1>";
echo "<p>City: " . $city . "</p>";
echo "<p>Temperature: " . $temp . "°C</p>";

// 3. Log de auditoría seguro (Sin inyección de comandos)
error_log("Consulta de clima realizada para la ciudad: " . $city);
