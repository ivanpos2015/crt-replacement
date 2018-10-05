#pragma once
/*********
********** Dependencies: mutex.hpp
********** Description: list.hpp provides a thread-safe list with object references.
**********/

//std::move for when you don't want to use stl.
/*
namespace std {
template <typename T>
T&& move(T&& arg)
{
return static_cast<T&&>(arg);
};
template <typename T>
T&& move(T& arg)
{
return static_cast<T&&>(arg);
};
};
*/

template <typename T>
struct sListEntity {
	T value;
	sListEntity *prev, *next;
	bool bInList;
	size_t ref;
};

template <typename T>
class List;

template <typename T>
class ObjReference {
public:
	ObjReference(const List<T>& list):list(list), node(nullptr){ };
	ObjReference(const List<T>& list, sListEntity<T>* node) :list(list), node(node) {
		if (node)
			InterlockedIncrement(&node->ref);
	};
	ObjReference(ObjReference<T>&& ref):list(ref.list)
	{
		this->node = ref.node;
		ref.node = nullptr;
	};
	ObjReference(const ObjReference<T>& ref) :list(ref.list), node(ref.node)
	{
		if (node)
			InterlockedIncrement(&node->ref);
	};

	~ObjReference()
	{
		this->release();
	};

	void release()
	{
		if (node) {
			if (InterlockedDecrement(&node->ref) == NULL)
				const_cast<List<T>&>(list).remove(node);
			node = nullptr;
		}
	};

	T* operator->() const { return ptr(); };
	T& get() const { return node->value; };
	T* ptr() const { return node ? &node->value : nullptr; };
	bool isDeleted() const { return node->bInList == false; };
	size_t refcnt() { return node ? InterlockedExchangeAdd(&node->ref, 0) : NULL; };
	bool IsNull() const { return node == nullptr; };
	bool IsValid() const { return !IsNull(); };
	bool operator!=(const ObjReference<T>& other) const
	{
		return other.node != this->node;
	};
	void operator++()
	{
		MutexLocker locker(list.m);
		sListEntity<T>* tmp = next();
		this->release();
		if (node = tmp)
			InterlockedIncrement(&node->ref);
	};
	void operator=(const ObjReference<T>& ref)
	{
		MutexLocker locker(list.m);
		this->release();
		if (node = ref.node)
			InterlockedIncrement(&node->ref);
	};
	void operator=(ObjReference<T>&& ref)
	{
		MutexLocker locker(list.m);
		this->release();
		if (node = ref.node)
			ref.node = nullptr;
	};
private:
	template <typename T>
	friend class List;
	sListEntity<T>* get_obj() const { return node; };

	sListEntity<T>* next()
	{
		sListEntity<T>* tmp = node;
		while (tmp = tmp->next) {
			if (tmp->bInList)
				break;
		}
		return tmp;
	};
	sListEntity<T>* node;
	const List<T>& list;
};

template <typename T>
class ListIterator;

template <typename T>
class List {
public:
	List();
	List(const List<T>& list);
	List(List<T>&& list);
	~List();
	void operator=(List&& other);
	void operator=(const List& other);
	void remove(sListEntity<T>* node);
	void remove(const ObjReference<T>& ref) { this->remove(ref.get_obj()); };
	void remove(const T& value);
	void remove(T&& value);
	ObjReference<T> addandgetref(const T& value) { MutexLocker locker(m); add(value); return ObjReference<T>(*this, tail); };
	ObjReference<T> addandgetref(T&& value) { MutexLocker locker(m); add(std::move(value)); return ObjReference<T>(*this, tail); };
	void add(const T& value);
	void add(T&& value);
	void push(const T& value) { add(value); };
	void push(T&& value) { add(std::move(value)); };
	ObjReference<T> pop(); //pops last entity in list
	ObjReference<T> pop_front(); //pops first entity in list
	List& operator<<(const T& value) { push(value); return *this; };
	List& operator<<(T&& value) { push(std::move(value)); return *this; };
	size_t size() const { return InterlockedExchangeAdd(&cnt, NULL); };
	void clear();
	ObjReference<T> operator[](size_t i) const { return this->at(i); };
	ObjReference<T> at(size_t index) const;
	ObjReference<T> makeref(const T& value) const;
	//ObjReference<T> makeref(T value) const;

	ListIterator<T> begin() const;
	ListIterator<T> end() const;
private:
	void clrnode(sListEntity<T>* node);
	friend class ObjReference<T>;
	bool IsHeadNull() { if (size()) return false; MutexLocker l(m); return head == nullptr; };
	sListEntity<T> *head, *tail;
	mutable size_t cnt;
	Mutex m;
};

template<typename T>
inline List<T>::List()
{
	cnt = NULL;
	head = tail = nullptr;
}

template<typename T>
inline List<T>::List(const List<T>& list):List()
{
	for (const auto& p : const_cast<List<T>&>(list))
		this->push(p);
}

template<typename T>
inline List<T>::List(List<T>&& other):List()
{
	MutexLocker locker(other.m);
	MutexLocker locker2(this->m);
	this->head = other.head;
	this->tail = other.tail;
	this->cnt = other.cnt;
	other.cnt = NULL;
	other.tail = other.head = nullptr;
}

template<typename T>
inline List<T>::~List()
{
	this->clear();
	while (!IsHeadNull())
		Sleep(20);
}

template<typename T>
inline void List<T>::operator=(List&& other)
{
	this->clear();
	MutexLocker l(other.m), l2(this->m);
	this->head = other.head;
	this->tail = other.tail;
	this->cnt = InterlockedExchange(&other.cnt, NULL);
	other.tail = other.head = nullptr;
}

template<typename T>
inline void List<T>::operator=(const List& other)
{
	this->clear();
	for (const auto& p : other)
		this->push(p);
}

template<typename T>
inline void List<T>::remove(sListEntity<T>* node)
{
	if (node == nullptr)
		return;
	MutexLocker locker(m);
	//note: perhaps we should check if the node is still linked.

	if (node->bInList) {
		InterlockedDecrement(&cnt);
		if (InterlockedDecrement(&node->ref) == NULL) {
			this->clrnode(node);
			delete node;
		}
		else
			node->bInList = false;
	}
	else {
		if (InterlockedExchangeAdd(&node->ref, NULL) == NULL) {
			this->clrnode(node);
			delete node;
		}
	}
}

template<typename T>
inline void List<T>::remove(const T & value)
{
	MutexLocker locker(m);
	if (sListEntity<T>* tmp = head)
		while (tmp) {
			if (&tmp->value == &value) {
				this->remove(tmp);
				break;
			}
			tmp = tmp->next;
		}
}

template<typename T>
inline void List<T>::remove(T && value)
{
	MutexLocker locker(m);
	if (sListEntity<T>* tmp = head)
		while (tmp) {
			if (tmp->value == value) {
				this->remove(tmp);
				break;
			}
			tmp = tmp->next;
		}
}

template<typename T>
inline void List<T>::add(const T& value)
{
	MutexLocker locker(m);
	if (head)
		tail = tail->next = new sListEntity<T>({ value, tail, nullptr, true, 1 });
	else
		tail = head = new sListEntity<T>({ value, nullptr, nullptr, true, 1 });
	InterlockedIncrement(&cnt);
}

template<typename T>
inline void List<T>::add(T&& value)
{
	MutexLocker locker(m);
	if (head)
		tail = tail->next = new sListEntity<T>({ std::move(value), tail, nullptr, true, 1 });
	else
		tail = head = new sListEntity<T>({ std::move(value), nullptr, nullptr, true, 1 });
	InterlockedIncrement(&cnt);
}

template <typename T>
inline ObjReference<T> List<T>::pop()
{
	MutexLocker locker(m);
	sListEntity<T> *entry = tail;
	while (entry) { //get last entry that's not deleted
		if (entry->bInList)
			break;
		entry = entry->prev;
	}
	auto ref = ObjReference<T>(*this, entry);
	this->remove(entry);
	return ref;
}

template <typename T>
inline ObjReference<T> List<T>::pop_front()
{
	MutexLocker locker(m);
	sListEntity<T> *entry = head;
	while (entry) { //get next entry that's not deleted
		if (entry->bInList)
			break;
		entry = entry->next;
	}
	auto ref = ObjReference<T>(*this, entry);
	this->remove(entry);
	return std::move(ref);
}


template<typename T>
inline void List<T>::clear()
{
	MutexLocker locker(m);
	if (sListEntity<T>* tmp = head)
		while (tmp) {
			sListEntity<T>* next = tmp->next;
			this->remove(tmp);
			tmp = next;
		}
}

template<typename T>
inline void List<T>::clrnode(sListEntity<T>* node)
{
	if (node->next)
		node->next->prev = node->prev;
	if (node->prev)
		node->prev->next = node->next;
	if (node == head)
		head = head->next;
	if (node == tail)
		tail = tail->prev;
}

template <typename T>
inline ObjReference<T> List<T>::at(size_t index) const
{
	size_t cIndex = NULL;
	MutexLocker locker(m);
	if (sListEntity<T>* tmp = head)
		while (tmp) {
			if (tmp->bInList)
				if (cIndex++ == index)
					return ObjReference<T>(*this, tmp);
			tmp = tmp->next;
		}
	return ObjReference<T>(*this, nullptr);
}

template <typename T>
inline ObjReference<T> List<T>::makeref(const T& value) const
{
	MutexLocker locker(m);
	if (sListEntity<T>* tmp = head)
		while (tmp) {
			if (&tmp->value == &value)
				return ObjReference<T>(*this, tmp);
			tmp = tmp->next;
		}
	return ObjReference<T>(*this, nullptr);
}

/*
template <typename T>
inline ObjReference<T> List<T>::makeref(const T value) const
{
	MutexLocker locker(m);
	if (sListEntity<T>* tmp = head)
		while (tmp) {
			if (tmp->value == value)
				return ObjReference<T>(*this, tmp);
			tmp = tmp->next;
		}
	return ObjReference<T>(*this, nullptr);
}
*/

template <typename T>
class ListIterator {
public:
	ListIterator(ObjReference<T>&& reference) :reference(std::move(reference)) {};
	void operator++() { ++reference; };
	T& operator*() const { return reference.get(); };
	bool operator!= (const ListIterator<T>& other) const { return reference != other.reference; };
private:
	ObjReference<T> reference;
};

template<typename T>
inline ListIterator<T> List<T>::begin() const
{
	MutexLocker locker(m);
	sListEntity<T>* tmp = head;
	while (tmp) {
		if (tmp->bInList)
			break;
		tmp = tmp->next;
	}
	return ListIterator<T>(ObjReference<T>(*this, tmp));
}

template<typename T>
inline ListIterator<T> List<T>::end() const
{
	return ListIterator<T>(ObjReference<T>(*this));
}