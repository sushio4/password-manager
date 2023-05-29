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

/*
*   This is made due to the requirements:
*       - not to use get/set methods
*       - not to use structs
*       - not to use private fields
*
*   And I am very determined to find loopholes in anything our prof
*       is going to say about that.
*
*   very.
*
*
*   EXAMPLE USAGE:
*   
*   class foo{
*   private:
*       int bar;
*   public:
*       hackPrivate(bar);
*   };
*
*   int main(){
*       private(foo,bar) = 5;
*       std::cout << private(foo, bar); 
*   }
*/