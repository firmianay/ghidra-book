#include <iostream>
#include <ctime>

class BaseClass {
public:
   BaseClass();
   virtual void vfunc1() = 0;
   virtual void vfunc2();
   virtual void vfunc3();
   virtual void vfunc4();
private:
   int x;
   int y;
};

class SubClass : public BaseClass {
public:
	SubClass();
	virtual void vfunc1();
	virtual void vfunc3();
	virtual void vfunc5();
private:
	int z;
};

class SubSubClass : public SubClass {
public:
	SubSubClass();
	virtual void vfunc3();
private:
	int z;
};

BaseClass::BaseClass() {
	std::cout << "Base Class constructor called" << std::endl;
}

void BaseClass::vfunc2() {
	std::cout << "Base Class vfunc2() called" << std::endl;
}

void BaseClass::vfunc3() {
	std::cout << "Base Class vfunc3() called" << std::endl;
}

void BaseClass::vfunc4() {
	std::cout << "Base Class vfunc4() called" << std::endl;
}

SubClass::SubClass() {
	std::cout << "Sub Class constructor called" << std::endl;
}

void SubClass::vfunc1() {
	std::cout << "Sub Class vfunc1() called" << std::endl;
}

void SubClass::vfunc3() {
	std::cout << "Sub Class vfunc3() called" << std::endl;
}

void SubClass::vfunc5() {
	std::cout << "Sub Class vfunc5() called" << std::endl;
}

SubSubClass::SubSubClass() {
	std::cout << "Sub Sub Class constructor called" << std::endl;
}

void SubSubClass::vfunc3() {
	std::cout << "Sub Sub Class vfunc3() called" << std::endl;
}


void call_vfunc(BaseClass *bc_ptr) {
   bc_ptr->vfunc3();
}

int main() {
   BaseClass *bc_ptr = new SubClass();
   std::cout << "typdeid(bc_ptr)  = " << typeid(bc_ptr).name() << std::endl;
   std::cout << "typdeid(*bc_ptr) = " << typeid(*bc_ptr).name() << std::endl;
   call_vfunc(bc_ptr);

   SubClass *sc_ptr = dynamic_cast<SubClass*>(bc_ptr);
   std::cout << "typdeid(sc_ptr)  = " << typeid(sc_ptr).name() << std::endl;
   std::cout << "typdeid(*sc_ptr) = " << typeid(*sc_ptr).name() << std::endl;
   call_vfunc(sc_ptr);

   BaseClass *bc_ptr_2;
   srand(time(0));
   if (rand() % 2) {
	   bc_ptr_2 = dynamic_cast<SubClass*>(new SubClass());
   }
   else {
	   bc_ptr_2 = dynamic_cast<SubClass*>(new SubSubClass());
   }
   std::cout << "typdeid(bc_ptr_2)  = " << typeid(bc_ptr_2).name() << std::endl;
   std::cout << "typdeid(*bc_ptr_2) = " << typeid(*bc_ptr_2).name() << std::endl;
   call_vfunc(bc_ptr_2);

   return 0;
}

