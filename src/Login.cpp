#include "Login.hpp"

LoginModule::LoginModule(std::shared_ptr<SyncModule>& syncRef, std::shared_ptr<CipherModule>& cipherRef)
{
    sync = syncRef;
    cipher = cipherRef;
}