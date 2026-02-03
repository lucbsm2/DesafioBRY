# Teste Técnico BRY

 O sistema é dividido em dois executáveis principais:

### CLI Tool (Bry_CLI): Executa o fluxo sequencial no terminal:

	Etapa 1: Calcula o Hash SHA-512 do arquivo.

	Etapa 2: Assina o documento digitalmente (Padrão CMS/PKCS#7 Attached).

	Etapa 3: Verifica a assinatura gerada, garantindo integridade e autoria.

### API Server (Bry_API): Servidor HTTP que expõe endpoints para integração externa.

	POST /signature: Responsável por gerar a assinatura digital de um arquivo enviado.

	POST /verify: Responsável por validar uma assinatura CMS e retornar os dados da verificação.


## Instalação e Build

### 1. Instalar o Conan

```
pip install conan
```

### 2. Baixar dependências e Compilar

Na raiz do projeto execute

```
# 1. Instalar bibliotecas (OpenSSL, Poco, GTest)
conan install . --output-folder=build --build=missing -s build_type=Release

# 2. Configurar o CMake
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release

# 3. Compilar o Projeto
cmake --build . --config Release
```


## Execução

Note que para essa etapa, a senha do certificado deve ser posta em um arquivo .env
	
P12_PASSWORD=XXXXXX

### CLI

```
cd build/Release
.\Bry_CLI.exe
```

### API

Iniciada na porta 8080

```
cd build/Release
.\Bry_API.exe
```

## Documentação dos Endpoints
	

#### POST /signature

	Body (Multipart/Form-Data):

		file: O arquivo a ser assinado.

		p12: O arquivo do certificado (.pfx/.p12).

		password: A senha do certificado.

	Resposta: String Base64 contendo a assinatura CMS.



#### POST /verify

	Body (Multipart/Form-Data):

		file: O arquivo de assinatura (.p7s).

	Resposta (JSON):

		JSON

		{
		  "status": "VALIDO",
		  "infos": {
			"nome_signatario": "Empresa X",
			"data_assinatura": "Feb 1 10:00:00 2026 GMT",
			"hash_documento": "A1B2C3...",
			"algoritmo_hash": "sha512"
		  }
		}

## Execução de testes

O projeto utiliza Google Test. Para rodar a suíte de testes:

```
cd build
ctest -C Release --output-on-failure
```

## Estrutura

```
.
├── src/                # Código-fonte
├── tests/              # Testes unitários
├── resources/
│   └── arquivos/       # Arquivos de exemplo para assinatura
├── CMakeLists.txt
├── conanfile.txt
├── CMakePresets.json
└── README.md

```