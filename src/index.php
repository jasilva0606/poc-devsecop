<?php
// API de Clima con fallos intencionales
header('Content-Type: application/json');

// ERROR: XSS Reflejado (SonarCloud/StackHawk lo verán)
$user_input = $_GET['city'] ?? 'Buenos Aires';
if (isset($_GET['debug'])) {
    echo "Iniciando búsqueda para: " " . $user_input; // Punto de inyección
}

// ERROR: Uso de shell_exec inseguro (SAST lo marcará)
// Simula un ping a un servidor de clima
if (isset($_GET['ping'])) {
    $host = $_GET['ping'];
    echo shell_exec("ping -c 1 " . $host);
}

$weatherData = [
    "city" => $user_input,
    "temp" => rand(10, 35) . "C"
];

echo json_encode($weatherData);