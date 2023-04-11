#ifndef ___VECTOR_UTILS_BASICS
#define ___VECTOR_UTILS_BASICS

#include <iostream>
#include <vector>
#include <cmath>
#include <stdexcept>

using namespace std;

template <typename T1, typename T2>
void operator+=(vector<T1>& u, const vector<T2>& v){
	if (v.size() != u.size())
		throw std::invalid_argument("It is impossible to add vectors of different sizes.");
	unsigned int n = u.size();
	for (unsigned int i = 0; i < n; i++){
		u[i] = u[i] + v[i];
	}
}

template <typename T1, typename T2>
void operator-=(vector<T1>& u, const vector<T2>& v){
	if (v.size() != u.size())
		throw std::invalid_argument("It is impossible to subtract vectors of different sizes.");
	unsigned int n = u.size();
	for (unsigned int i = 0; i < n; i++){
		u[i] = u[i] - v[i];
	}
}

// entrywise multiplication
template <typename T1, typename T2>
void operator*=(vector<T1>& u, const vector<T2>& v){
	unsigned int n = u.size();
	for (unsigned int i = 0; i < n; i++){
		u[i] *= v[i];
	}
}

// entrywise division
template <typename T1, typename T2>
void operator/=(vector<T1>& u, const vector<T2>& v){
	unsigned int n = u.size();
	for (unsigned int i = 0; i < n; i++){
		u[i] /= v[i];
	}
}

template <typename T1, typename T2>
vector<T1> operator+(const vector<T1>& u, const vector<T2>& v){
	vector<T1> vec(u);
	vec += v;
	return vec;
}

template <typename T1, typename T2>
vector<T1> operator-(const vector<T1>& u, const vector<T2>& v){
	vector<T1> vec(u);
	vec -= v;
	return vec;
}

// entrywise multiplication
template <typename T1, typename T2>
vector<T1> operator*(const vector<T1>& u, const vector<T2>& v){
	vector<T1> vec(u);
	vec *= v;
	return vec;
}

// entrywise division
template <typename T1, typename T2>
vector<T1> operator/(const vector<T1>& u, const vector<T2>& v){
	vector<T1> vec(u);
	vec /= v;
	return vec;
}

// add all the elements
template <typename ELEMENT>
ELEMENT sum(const vector<ELEMENT>& u){
    ELEMENT s = u[0];
    for(unsigned int i = 1; i < u.size(); i++){
        s += u[i];
    }
	return s;
}


// add all the elements
template <typename ELEMENT>
ELEMENT sum_mod(const vector<ELEMENT>& u, ELEMENT modulus){
    ELEMENT s = u[0];
    for(unsigned int i = 1; i < u.size(); i++){
        s += u[i];
        s %= modulus;
    }
	return s;
}



template <typename ELEMENT>
std::ostream& operator<<(std::ostream& os, const vector<ELEMENT>& u){
	unsigned int lastPosition = u.size() - 1;
	for (unsigned int i = 0; i < lastPosition; i++){
		os << u[i] << ", ";
	}
	os << u[lastPosition];
	return os;
}

#endif
