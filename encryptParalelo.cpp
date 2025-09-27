/*Lab07 Microprocesadores
Jackelyn Girón 24737
Sepriembre 2025
Encriptacion y desencriptacion en paralelo usando AES-256-CBC
*/
#include <bits/stdc++.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

const size_t BLOQUE = 1024 * 1024;

static void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; ++i){
        cout << hex << setw(2)<< setfill('0')<< (int)buf[i];
    }
    cout << dec << endl;
}

static bool hex_to_bytes(const string &hex, unsigned char *out, size_t outlen) {
    if (hex.size() != outlen * 2) return false;
    for (size_t i = 0; i < outlen; ++i) {
        unsigned int byte;
        if (sscanf(hex.c_str() + 2*i, "%2x", &byte) != 1) return false;
        out[i] = (unsigned char)byte;
    }
    return true;
}

static uint64_t file_size_from_fd(int fd) {
    struct stat st;
    if (fstat(fd, &st) < 0) return 0;
    return (uint64_t)st.st_size;
}

//Funcion para generar el nombre de salida de los archivos al encriptar y desencriptar
static string outputFileName(const string &input_file, bool is_encrypt) {
    if (is_encrypt) {
        size_t last_slash = input_file.find_last_of("/\\");
        string filename = (last_slash != string::npos) ? input_file.substr(last_slash + 1) : input_file;
        
        size_t dot_pos = filename.find_last_of('.');
        string base_name = (dot_pos != string::npos) ? filename.substr(0, dot_pos) : filename;
        
        return "salida" + base_name + ".enc";
    } else {
        size_t dot_pos = input_file.find_last_of('.');
        if (dot_pos != string::npos && input_file.substr(dot_pos) == ".enc") {
            return input_file.substr(0, dot_pos) + ".dec";
        } else {
            return input_file + ".dec";
        }
    }
}

struct BloqueResultado {
    size_t indice;
    vector<unsigned char> iv;   // 16 bytes
    vector<unsigned char> data; // ciphertext o plaintext
};

//hilos de encriptacion
struct EncArgs {
    int input_fd;
    size_t bloque_size;
    uint64_t file_size;
    unsigned char key[32];
    atomic_size_t *next_idx;
    unordered_map<size_t, BloqueResultado> *results;
    mutex *m;
    condition_variable *cv;
};

//hilos de desencriptacion
struct DecArgs {
    vector<pair<vector<unsigned char>, vector<unsigned char>>> *cipher_blocks; 
    unsigned char key[32];
    atomic_size_t *next_idx;
    unordered_map<size_t, BloqueResultado> *results;
    mutex *m;
    condition_variable *cv;
};

// --- AES wrappers (EVP) ---
static bool aes256_cbc_encrypt(const unsigned char *key,
                               const unsigned char *iv,
                               const unsigned char *in, int in_len,
                               vector<unsigned char> &out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int ok = 0;
    out.resize(in_len + EVP_MAX_BLOCK_LENGTH);
    int out1 = 0, out2 = 0;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) goto end;
    if (1 != EVP_EncryptUpdate(ctx, out.data(), &out1, in, in_len)) goto end;
    if (1 != EVP_EncryptFinal_ex(ctx, out.data() + out1, &out2)) goto end;
    out.resize(out1 + out2);
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok == 1;
}

static bool aes256_cbc_decrypt(const unsigned char *key,
                               const unsigned char *iv,
                               const unsigned char *in, int in_len,
                               vector<unsigned char> &out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int ok = 0;
    out.resize(in_len + EVP_MAX_BLOCK_LENGTH);
    int out1 = 0, out2 = 0;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) goto end;
    if (1 != EVP_DecryptUpdate(ctx, out.data(), &out1, in, in_len)) goto end;
    if (1 != EVP_DecryptFinal_ex(ctx, out.data() + out1, &out2)) goto end;
    out.resize(out1 + out2);
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    return ok == 1;
}

//worker de encriptacion
static void *enc_worker(void *arg) {
    EncArgs *A = (EncArgs*)arg;
    while (true) {
        size_t idx = A->next_idx->fetch_add(1);
        size_t nblocks = (size_t)((A->file_size + A->bloque_size - 1) / A->bloque_size);
        if (idx >= nblocks) break;
        uint64_t offset = (uint64_t)idx * A->bloque_size;
        size_t to_read = A->bloque_size;
        if (offset + to_read > A->file_size) to_read = (size_t)(A->file_size - offset);
        vector<unsigned char> inbuf(to_read);
        ssize_t r = pread(A->input_fd, inbuf.data(), to_read, offset);
        if (r <= 0) {
            fprintf(stderr, "Error leyendo bloque %zu\n", idx);
            continue;
        }
        unsigned char iv_local[16];
        if (!RAND_bytes(iv_local, sizeof(iv_local))) {
            fprintf(stderr, "Error generando IV en bloque %zu\n", idx);
            continue;
        }
        vector<unsigned char> ciphertext;
        if (!aes256_cbc_encrypt(A->key, iv_local, inbuf.data(), (int)to_read, ciphertext)) {
            fprintf(stderr, "Encrypt falló en bloque %zu\n", idx);
            continue;
        }
        BloqueResultado br;
        br.indice = idx;
        br.iv.assign(iv_local, iv_local + 16);
        br.data = move(ciphertext);

        {
            unique_lock<mutex> lk(*A->m);
            (*A->results)[idx] = move(br);
        }
        A->cv->notify_one();
    }
    delete A;
    return nullptr;
}

//worker de desencriptacion
static void *dec_worker(void *arg) {
    DecArgs *A = (DecArgs*)arg;
    size_t nblocks = A->cipher_blocks->size();
    while (true) {
        size_t idx = A->next_idx->fetch_add(1);
        if (idx >= nblocks) break;
        auto &blk = (*A->cipher_blocks)[idx];
        vector<unsigned char> plaintext;
        if (!aes256_cbc_decrypt(A->key, blk.first.data(), blk.second.data(), (int)blk.second.size(), plaintext)) {
            fprintf(stderr, "Decrypt falló en bloque %zu\n", idx);
            plaintext.clear();
        }
        BloqueResultado br;
        br.indice = idx;
        br.iv = blk.first;
        br.data = move(plaintext);
        {
            unique_lock<mutex> lk(*A->m);
            (*A->results)[idx] = move(br);
        }
        A->cv->notify_one();
    }
    delete A;
    return nullptr;
}

//Funcion principal para encriptar en paralelo 
bool encriptar_paralelo(const string &inputFile, const string &outputFile, int nthreads, unsigned char out_key[32]) {
    int infd = open(inputFile.c_str(), O_RDONLY);
    if (infd < 0) { perror("open input"); return false; }
    uint64_t fsz = file_size_from_fd(infd);
    size_t nblocks = (size_t)((fsz + BLOQUE - 1) / BLOQUE);

    if (!RAND_bytes(out_key, 32)) { fprintf(stderr, "Error generando clave\n"); close(infd); return false; }

    ofstream out(outputFile, ios::binary | ios::trunc);
    if (!out) { fprintf(stderr, "No fue posible abrir archivo salida\n"); close(infd); return false; }
    out.write("PENC", 4);
    uint8_t ver = 1; out.write((char*)&ver, 1);
    out.write((char*)&fsz, sizeof(fsz));
    uint32_t bs32 = (uint32_t)BLOQUE; out.write((char*)&bs32, sizeof(bs32));
    uint32_t nb32 = (uint32_t)nblocks; out.write((char*)&nb32, sizeof(nb32));
    out.flush();

    unordered_map<size_t, BloqueResultado> results;
    mutex m;
    condition_variable cv;
    atomic_size_t next_idx(0);

    //creacion de hilos para encriptar
    vector<pthread_t> threads(nthreads);
    for (int i = 0; i < nthreads; ++i) {
        EncArgs *arg = new EncArgs();
        arg->input_fd = infd;
        arg->bloque_size = BLOQUE;
        arg->file_size = fsz;
        memcpy(arg->key, out_key, 32);
        arg->next_idx = &next_idx;
        arg->results = &results;
        arg->m = &m;
        arg->cv = &cv;
        pthread_create(&threads[i], nullptr, enc_worker, arg);
    }

    // escritor los espera bloques en orden
    for (size_t expect = 0; expect < nblocks; ++expect) {
        unique_lock<mutex> lk(m);
        cv.wait(lk, [&]{ return results.find(expect) != results.end(); });
        BloqueResultado br = move(results[expect]);
        results.erase(expect);
        lk.unlock();

        uint64_t clen = (uint64_t)br.data.size();
        out.write((char*)br.iv.data(), 16);
        out.write((char*)&clen, sizeof(clen));
        out.write((char*)br.data.data(), br.data.size());
    }

    for (int i = 0; i < nthreads; ++i) pthread_join(threads[i], nullptr);

    out.close();
    close(infd);
    return true;
}

//Funcion principal para desencriptar en paralelo
bool desencriptar_paralelo(const string &inputFile, const string &outputFile, int nthreads, const unsigned char key_in[32]) {
    ifstream in(inputFile, ios::binary);
    if (!in) { fprintf(stderr, "No fue posible abrir archivo encriptado\n"); return false; }
    char magic[4]; in.read(magic, 4);
    if (strncmp(magic, "PENC", 4) != 0) { fprintf(stderr, "Formato de archivo no reconocido\n"); return false; }
    uint8_t ver; in.read((char*)&ver, 1);
    uint64_t orig_size; in.read((char*)&orig_size, sizeof(orig_size));
    uint32_t block_size; in.read((char*)&block_size, sizeof(block_size));
    uint32_t nblocks; in.read((char*)&nblocks, sizeof(nblocks));

    // leer los bloques (IV + len + ciphertext) en memoria
    vector<pair<vector<unsigned char>, vector<unsigned char>>> cipher_blocks;
    cipher_blocks.reserve(nblocks);
    for (uint32_t i = 0; i < nblocks; ++i) {
        vector<unsigned char> iv(16);
        in.read((char*)iv.data(), 16);
        uint64_t clen; in.read((char*)&clen, sizeof(clen));
        vector<unsigned char> ciph((size_t)clen);
        in.read((char*)ciph.data(), clen);
        cipher_blocks.emplace_back(move(iv), move(ciph));
    }
    in.close();

    unordered_map<size_t, BloqueResultado> results;
    mutex m;
    condition_variable cv;
    atomic_size_t next_idx(0);

    //hilos desencriptado
    vector<pthread_t> threads(nthreads);
    for (int i = 0; i < nthreads; ++i) {
        DecArgs *arg = new DecArgs();
        arg->cipher_blocks = &cipher_blocks;
        memcpy(arg->key, key_in, 32);
        arg->next_idx = &next_idx;
        arg->results = &results;
        arg->m = &m;
        arg->cv = &cv;
        pthread_create(&threads[i], nullptr, dec_worker, arg);
    }

    // escritor para escribir bloques desencriptados en orden
    ofstream out(outputFile, ios::binary | ios::trunc);
    if (!out) { fprintf(stderr, "No se pudo crear archivo de salida\n"); return false; }

    for (size_t expect = 0; expect < cipher_blocks.size(); ++expect) {
        unique_lock<mutex> lk(m);
        cv.wait(lk, [&]{ return results.find(expect) != results.end(); });
        BloqueResultado br = move(results[expect]);
        results.erase(expect);
        lk.unlock();
        out.write((char*)br.data.data(), br.data.size());
    }

    for (int i = 0; i < nthreads; ++i) pthread_join(threads[i], nullptr);

    out.close();
    return true;
}

int main() {
    ios::sync_with_stdio(false);
    bool continuar = true;

    while (continuar) {
        cout << "Encriptacion paralela AES-256-CBC con bloques de 1MB\n";
        cout << "\n1) Encriptar archivo\n 2) Desencriptar archivo\n 0) Salir\n";
        cout << "Ingrese la opcion que deseea ejecutar: ";
        int opt; 
        if (!(cin >> opt)) return 0;

        if (opt == 1) {
            string inFile;
            int nthreads;
            cout << "Ingrese el nombre del archivo a encriptar con la extension: "; 
            cin >> inFile;
            cout << "Numero de hilos: "; 
            cin >> nthreads;
            cin.ignore();

            string outFile = outputFileName(inFile, true);
            cout << "\nEl nombre del archivo encriptado es: " << outFile << "\n";
            
            unsigned char key[32];
            bool ok = encriptar_paralelo(inFile, outFile, nthreads, key);
            if (!ok){ 
                cerr << "Encriptacion fallida\n";
                return 1;
            }
            cout << "Encriptacion terminada con exito\n";
            cout << "GUARDAR LA CLAVE PARA DESENCRIPTAR: ";
            print_hex(key, 32);
            cout << "\n";
            
        } else if (opt == 2) {
            string inFile, hexkey;
            int nthreads;
            cout << "Ingrese el nombre del archivo a desencriptar con la extension: "; cin >> inFile;
            cout << "Numero de hilos: "; 
            cin >> nthreads;
            cout << "Introducir la clave: "; 
            cin >> hexkey;
            
            string outFile = outputFileName(inFile, false);
            cout << "\nArchivo de salida: " << outFile << "\n";
            
            unsigned char key[32];
            if (!hex_to_bytes(hexkey, key, 32)) { cerr << "Clave hex invalida\n"; return 1; }
            bool ok = desencriptar_paralelo(inFile, outFile, nthreads, key);
            if (!ok) { cerr << "Desencriptacion fallida\n"; return 1; }
            cout << "Desencriptacion terminada con exito";
        } else if(opt == 0) {
            continuar = false;
            cout << "Saliendo del programa\n";
        } else {
            cout << "Opcion invalida\n";
        }
    }
    return 0;
}