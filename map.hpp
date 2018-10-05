#pragma once
/*********
********** Dependencies: list.hpp
********** Description: map.hpp 
**********/

template <typename K, typename V>
class Pair {
public:
	Pair(const K& k, const V& v) :key(k), value(v) {};
	Pair(const Pair& pair):key(pair.key), value(pair.value) {};
	Pair(Pair&& pair) :key(pair.key), value(pair.value) {};
	void operator=(const V& value);
	K key;
	V value;
};

template<typename K, typename V>
inline void Pair<K, V>::operator=(const V & value)
{
	this->value = value;
}

template <typename K, typename V>
class Map {
public:
	Map() {};
	Map(Map&& other):pairs(std::move(other.pairs)) {}
	ObjReference<Pair<K, V>> operator[](const K& key) { return this->at(key); };
	ObjReference<Pair<K, V>> at(const K& key);
	ListIterator<Pair<K, V>> begin() { return pairs.begin(); };
	ListIterator<Pair<K, V>> end() { return pairs.end(); };
	bool find(const K& key) {
		for (auto& pair : pairs) {
			if (pair.key == key)
				return true;
		}
		return false;
	};
	size_t size() { return pairs.size(); };
	void clear() { pairs.clear(); };
	bool isEmtpy() { return 0 == pairs.size(); };
	void add(const Pair<K, V>& pair) {
		pairs.add(pair);
	};
	void add(Pair<K, V>&& pair) {
		pairs.add(std::move(pair));
	};
	void remove(const Pair<K, V>& p) { pairs.remove(p); };
	void remove(const K& key) {
		for (auto& pair : pairs)
			if (pair.key == key) {
				pairs.remove(pair);
				break;
			}
	};
private:
	List<Pair<K, V>> pairs;
};

template<typename K, typename V>
inline ObjReference<Pair<K, V>> Map<K, V>::at(const K & key)
{
	for (auto& pair : pairs) {
		if (pair.key == key)
			return pairs.makeref(pair);
	}
	return ObjReference<Pair<K, V>>(pairs);
}