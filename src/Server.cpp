#include "Poco/Net/HTTPServer.h"
#include "Poco/Net/HTTPRequestHandler.h"
#include "Poco/Net/HTTPRequestHandlerFactory.h"
#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/Net/HTTPServerResponse.h"
#include "Poco/Net/ServerSocket.h"
#include "Poco/Net/HTMLForm.h"
#include "Poco/Net/PartHandler.h"
#include "Poco/Net/MessageHeader.h"
#include "Poco/JSON/Object.h"
#include "Poco/Base64Encoder.h"
#include "Poco/StreamCopier.h"
#include "Poco/URI.h"
#include "Poco/TemporaryFile.h"
#include "Poco/Path.h"


#include <iostream>
#include <fstream>
#include <sstream>
#include <map>

#include "SignerService.h"
#include "VerifierService.h"
#include "Utils.h"

using namespace Poco::Net;

// ------------------------------------------------------------------
// PartHandler: Handles multipart file uploads by saving to disk
// ------------------------------------------------------------------
class TempFilePartHandler : public PartHandler {
public:
    // Map: "form_field_name" -> "file_path_on_disk"
    std::map<std::string, std::string> files;

    void handlePart(const MessageHeader& header, std::istream& stream) override {
        if (header.has("Content-Disposition")) {
            std::string disp;
            NameValueCollection params;
            MessageHeader::splitParameters(header.get("Content-Disposition"), disp, params);
            
            std::string name = params.get("name", "");
            std::string filename = params.get("filename", "");
            
            // Skip non-file fields (handled by HTMLForm)
            if (filename.empty()) {
                return;
            }
            
            // Create a temp file that persists until manually deleted or process exit
            Poco::TemporaryFile tempFile;
            tempFile.keepUntilExit();
            std::string tempFileName = tempFile.path();
            
            std::ofstream out(tempFileName, std::ios::binary);
            Poco::StreamCopier::copyStream(stream, out);
            out.close();

            files[name] = tempFileName;
        }
    }
};

// ------------------------------------------------------------------
// Endpoint: POST /signature
// Expects: file, p12, password
// Returns: Base64 encoded CMS signature
// ------------------------------------------------------------------
class SignatureHandler : public HTTPRequestHandler {
public:
    void handleRequest(HTTPServerRequest& request, HTTPServerResponse& response) override {
        response.set("Access-Control-Allow-Origin", "*");

        if (request.getMethod() != "POST") {
            response.setStatus(HTTPResponse::HTTP_METHOD_NOT_ALLOWED);
            response.send();
            return;
        }
        
        try {
            TempFilePartHandler partHandler;
            HTMLForm form(request, request.stream(), partHandler);

            std::string password = form.get("password", "");
            
            // Validate required parameters
            if (partHandler.files.find("file") == partHandler.files.end() || 
                partHandler.files.find("p12") == partHandler.files.end() || 
                password.empty()) {
                
                response.setStatus(HTTPResponse::HTTP_BAD_REQUEST);
                response.send() << "Missing parameters: file, p12, or password.";
                return;
            }

            std::string docPath = partHandler.files["file"];
            std::string p12Path = partHandler.files["p12"];
            
            // Construct output path robustly
            Poco::Path docPathObj(docPath);
            std::string docDir = docPathObj.parent().toString();
            std::string docBaseName = docPathObj.getBaseName();    
            std::string sigPath = docDir + docBaseName + "_signed.p7s";

            bool success = SignerService::generateSignature(p12Path, password, docPath, sigPath);

            // Cleanup inputs immediately
            std::remove(docPath.c_str());
            std::remove(p12Path.c_str());

            if (success) {
                // Read binary signature and encode to Base64
                std::ifstream sigFile(sigPath, std::ios::binary);
                std::ostringstream oss;
                
                Poco::Base64Encoder encoder(oss);
                Poco::StreamCopier::copyStream(sigFile, encoder);
                encoder.close(); 

                response.setContentType("text/plain");
                response.send() << oss.str();

                // Cleanup output file
                //std::remove(sigPath.c_str());
            } else {
                response.setStatus(HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
                response.send() << "Failed to sign document.";
            }
        }     
        catch (const std::exception& e) {
            Utils::logInfo(std::string("Signature error: ") + e.what());
            response.setStatus(HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
            response.send() << "Internal server error";
        }
    }
};

// ------------------------------------------------------------------
// Endpoint: POST /verify
// Expects: file (CMS signature)
// Returns: JSON with verification details
// ------------------------------------------------------------------
class VerifyHandler : public HTTPRequestHandler {
public:
    void handleRequest(HTTPServerRequest& request, HTTPServerResponse& response) override {
        if (request.getMethod() != "POST") {
            response.setStatus(HTTPResponse::HTTP_METHOD_NOT_ALLOWED);
            response.send();
            return;
        }

        TempFilePartHandler partHandler;
        HTMLForm form(request, request.stream(), partHandler);

        if (partHandler.files.find("file") == partHandler.files.end()) {
            response.setStatus(HTTPResponse::HTTP_BAD_REQUEST);
            response.send() << "Falta o arquivo assinado (campo 'file').";
            return;
        }

        std::string sigPath = partHandler.files["file"];
        
        // Execute verification logic
        auto result = VerifierService::verifyAndGetDetails(sigPath);
        
        std::remove(sigPath.c_str());

        // Build JSON response
        Poco::JSON::Object json;
        json.set("status", result.status);

        if (result.isValid) {
            Poco::JSON::Object infos;
            infos.set("nome_signatario", result.signerName);
            infos.set("data_assinatura", result.signingTime);
            infos.set("hash_documento", result.hashHex);
            infos.set("algoritmo_hash", result.hashAlgo);
            json.set("infos", infos);
        }

        response.setContentType("application/json");
        std::ostream& out = response.send();
        json.stringify(out, 2);
    }
};

// ------------------------------------------------------------------
// Router Factory
// ------------------------------------------------------------------
class RequestFactory : public HTTPRequestHandlerFactory {
public:
    HTTPRequestHandler* createRequestHandler(const HTTPServerRequest& request) override {
        Poco::URI uri(request.getURI());
        std::string path = uri.getPath();

        if (path == "/signature") return new SignatureHandler();
        if (path == "/verify")    return new VerifyHandler();

        return nullptr;
    }
};

// ------------------------------------------------------------------
// Main Entry Point
// ------------------------------------------------------------------
int main() {
    try {
        
        std::srand(std::time(nullptr));

        // OpenSSL initialization
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

        ServerSocket svs(8080);
        HTTPServer srv(new RequestFactory(), svs, new HTTPServerParams);

        srv.start();
        std::cout << ">>> Server running on port 8080 <<<" << std::endl;
        std::cout << "Press ENTER to stop..." << std::endl;
        
        std::cin.get();
        
        srv.stop();

        EVP_cleanup();
        ERR_free_strings();

        std::cout << "Server stopped." << std::endl;

    }
    catch (std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}