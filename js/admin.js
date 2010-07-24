if (typeof jQuery!="undefined") {
	$(document).ready(function() {
		$('.help').each(function() {
			string = $(this).text();
			$(this).html('<img src="/wp-content/plugins/soap-auth/images/help.png" alt="' + string + '" title="' + string + '" class="tooltip" />');
		});
		tooltip();
	});
}else{
	alert("Could not find jQuery installed within your Wordpress installation, please download and enable it");
}

this.tooltip = function(){
	/* CONFIG */
		xOffset = 25;
		yOffset = 15;
		// these 2 variable determine popup's distance from the cursor
		// you might want to adjust to get the right result
	/* END CONFIG */
	$("img.tooltip").hover(function(e){
		this.t = this.title;
		this.title = "";
		$("body").append("<p id='tooltip'>"+ this.t +"</p>");
		$("#tooltip")
			.css("top",(e.pageY - xOffset) + "px")
			.css("left", (e.pageX + yOffset) + "px")
			.css("position", "absolute")
			.fadeIn("slow");
    },
	function(){
		this.title = this.t;
		$("#tooltip").remove();
    });
	$("img.tooltip").mousemove(function(e){
		$("#tooltip")
			.css("top",(e.pageY - xOffset) + "px")
			.css("left",(e.pageX + yOffset) + "px")
			.css("position", "absolute");
	});
};