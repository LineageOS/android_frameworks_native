extern "C" {
    void _ZN7android6Parcel13writeString16EPKDsj(char16_t const*, unsigned int);

    void _ZN7android6Parcel13writeString16EPKtj(unsigned short const* str, unsigned int len){
        _ZN7android6Parcel13writeString16EPKDsj((char16_t const*)str, len);
    }
}
