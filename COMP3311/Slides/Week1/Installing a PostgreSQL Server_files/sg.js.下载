

var curSlide = 0;

function nextSlide() {
	var nextSlide = parseInt(curSlide) + 1;
	window.location.href = "#s" +  nextSlide; 
}

function prevSlide(){
	var prevSlide = parseInt(curSlide) - 1;
	if(prevSlide >=0 ) {
		window.location.href = "#s" +  prevSlide; 
	}
}

$(document).ready(  function(){

	$(window).scroll(function() {	
		var windowTop = Math.max($('body').scrollTop(), $('html').scrollTop());
		$('.slideCl1').each( function (index) {
				if (windowTop > ($(this).position().top - 100)) {
					curSlide = $(this).attr('id');
					curSlide = curSlide.substring(1, curSlide.length); 
				}
		});		
	}).scroll();

	$( "body" ).keypress(function( event ) {
		  // 110 for 'n', 102 for 'f'
		  if (event.which == 110 || event.which == 102) {  
			nextSlide();
			event.preventDefault();
		  }
		  // 112 for 'p', 98 for 'b'
		  else if (event.which == 112 || event.which == 98) { 
			prevSlide();
			event.preventDefault();
		  }
		  // 104 for 'h'
		  else if (event.which == 104) {  
			window.location.href = "#s0"  
			event.preventDefault();
		  }
	});

	$( "body" ).keydown(function( event ) {
		  // 39 for right (40 for down)
		  if (event.which == 39) {  
			var nextSlide = parseInt(curSlide) + 1;
			window.location.href = "#s" +  nextSlide; 
			event.preventDefault();
		  }
		  //  37 for left (38 for up)
		  else if (event.which == 37) { 
			var prevSlide = parseInt(curSlide) - 1;
			if(prevSlide >=0 ) {
				window.location.href = "#s" +  prevSlide; 
				event.preventDefault();
			}
		  }

	});

});



