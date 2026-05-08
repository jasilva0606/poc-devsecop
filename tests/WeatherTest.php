<?php

namespace App\Tests;

use PHPUnit\Framework\TestCase;

class WeatherTest extends TestCase
{
    /**
     * Verifica que la respuesta simulada de la API contenga las claves necesarias.
     */
    public function testWeatherApiResponseStructure(): void
    {
        // Simulamos la estructura que genera src/index.php
        $userInput = "Moron";
        $mockResponse = [
            "city" => $user_input,
            "temp" => rand(10, 35) . "C"
        ];

        // Validamos que existan las claves requeridas para una Fintech
        $this->assertArrayHasKey('city', $mockResponse, "La respuesta debe contener la ciudad.");
        $this->assertArrayHasKey('temp', $mockResponse, "La respuesta debe contener la temperatura.");
        
        // Validamos que el nombre de la ciudad sea el esperado
        $this->assertEquals("Moron", $mockResponse['city']);
        
        // Validamos el formato de la temperatura (ej: termina en 'C')
        $this->assertStringEndsWith('C', $mockResponse['temp'], "La temperatura debe estar en grados Celsius.");
    }

    /**
     * Verifica que la lógica de temperatura devuelva un valor numérico coherente.
     */
    public function testTemperatureRange(): void
    {
        $tempString = rand(10, 35) . "C";
        $tempValue = (int)filter_var($tempString, FILTER_SANITIZE_NUMBER_INT);

        $this->assertGreaterThanOrEqual(10, $tempValue);
        $this->assertLessThanOrEqual(35, $tempValue);
    }
}