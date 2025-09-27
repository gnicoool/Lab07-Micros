/*
 *-----------------------------------------------------------
 * EncriptacionSecuencial.cpp
 *-----------------------------------------------------------
 * UNIVERSIDAD DEL VALLE DE GUATEMALA
 * Facultad de Ingenieria
 * Departamento de Ciencia de la Computacion
 *
 * Descripcion:
 * Encripta de forma secuencial el contenido de un archivo
 * utilizando la libreria OpenSSL (AES-256-CBC).
 *-----------------------------------------------------------
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

int main() {
    const char* inputFile = "input.txt";
    const char* outputFile = "salida.enc";

    // Clave y vector de inicializacion (IV)
    unsigned char key[32];  // 256 bits
    unsigned char iv[16];   // 128 bits

    // Generar valores aleatorios para clave e IV
    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        cerr << "Error generando clave o IV" << endl;
        return 1;
    }

    // Abrir archivo de entrada
    ifstream inFile(inputFile, ios::binary);
    if (!inFile) {
        cerr << "No se pudo abrir archivo de entrada" << endl;
        return 1;
    }

    // Leer contenido del archivo
    vector<unsigned char> buffer((istreambuf_iterator<char>(inFile)),
                                 istreambuf_iterator<char>());
    inFile.close();

    // Preparar contexto de cifrado
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "Error creando contexto" << endl;
        return 1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        cerr << "Error en EVP_EncryptInit_ex" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    // Encriptar datos
    vector<unsigned char> ciphertext(buffer.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          buffer.data(), buffer.size()) != 1) {
        cerr << "Error en EVP_EncryptUpdate" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        cerr << "Error en EVP_EncryptFinal_ex" << endl;
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Guardar encriptado en archivo
    ofstream outFile(outputFile, ios::binary);
    outFile.write((char*)iv, sizeof(iv)); // Guardamos IV al inicio
    outFile.write((char*)ciphertext.data(), ciphertext_len);
    outFile.close();

    cout << "Archivo encriptado guardado en " << outputFile << endl;
    cout << "Recuerda guardar la clave (no esta en el archivo)." << endl;

    // Mostrar clave en hexadecimal
    cout << "Clave generada: ";
    for (int i = 0; i < sizeof(key); i++)
        printf("%02x", key[i]);
    cout << endl;

    return 0;
}
