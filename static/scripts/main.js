var classToggle = function(element_id){
	var elements = document.getElementsByClassName('fp-nav-element');
	var e = document.getElementById(element_id)
	for (var i = 0; i < elements.length - 1; i++) {
		elements[i].classList.remove("active")
	};
	e.classList.add("active")
};
var classOff = function(){
	var elements = document.getElementsByClassName('fp-nav-element');
	for (var i = 0; i < elements.length - 1; i++) {
		elements[i].classList.remove("active")
	};
};