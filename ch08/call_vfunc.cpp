/*
   Copyright (c) 2008 Chris Eagle (cseagle at gmail d0t com)
   
   Permission is hereby granted, free of charge, to any person obtaining a copy of 
   this software and associated documentation files (the "Software"), to deal in 
   the Software without restriction, including without limitation the rights to 
   use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of 
   the Software, and to permit persons to whom the Software is furnished to do so, 
   subject to the following conditions:
   
   The above copyright notice and this permission notice shall be included in all 
   copies or substantial portions of the Software.
   
   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS 
   FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
   COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER 
   IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN 
   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "call_vfunc.h"

BaseClass::BaseClass() {
}

void BaseClass::vfunc2() {
}

void BaseClass::vfunc3() {
}

void BaseClass::vfunc4() {
}

SubClass::SubClass() {
}

void SubClass::vfunc1() {
}

void SubClass::vfunc3() {
}

void SubClass::vfunc5() {
}

void call_vfunc(BaseClass *bc) {
    bc->vfunc3();
}

int main() {
    BaseClass *bc = new SubClass();
    call_vfunc(bc);
}
