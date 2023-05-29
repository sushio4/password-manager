#include<type_traits>

template<typename T, typename U> constexpr 
unsigned long offsetOf(U T::*member)
{ 
    return (char*)&((T*)nullptr->*member) - (char*)nullptr; 
}

#define hackPrivate(X) decltype(X)& X ## 272271() {             \
    return *(decltype(X)*)(                                     \
        offsetOf(                                               \
            &std::remove_pointer<decltype(this)>::type::X       \
        ) + this                                                \
    );                                                          \
}

#define private(X, Y) (X.Y ## 272271())

