static const char kMetadataName[] =
    "NSt3__110__function6__funcIZN7Example6Worker3runEvE3$_0NS_9allocatorIS4_EEFvvEEE";

int anonymous_metadata_user(int x) {
    volatile const char* p = kMetadataName;
    return x + p[0];
}

int main(int argc, char** argv) {
    (void)argv;
    return anonymous_metadata_user(argc);
}
