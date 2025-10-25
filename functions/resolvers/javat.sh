#!/bin/bash

# This function is for compiling and calling the Java program
javat (){

	# Move inside the root directory of the project
	javanet_path="$default_path/javanet"
	cd "$javanet_path" || exit
	echo

	javat_compiler # Call the compiler

	javat_exec # Call the executor


}

# For compiling the Java program
javat_compiler(){

	mkdir -p bin

	# Delete previous .class files
	find "$javanet_path" -type f -name "*.class" | xargs rm 2>/dev/null

	# Compile the project and reorganize it
	echo -e "${turquoiseColour}[!] Compiling the java code...${endColour}"
	javac src/Classes/*java src/Main/*java
	#javac -cp ".:bin:lib/opencsv-5.7.1.jar" -d bin src/Classes/*.java src/Main/*.java 
	#javac -cp ".:bin:lib/opencsv-5.7.1.jar" -d bin src/Classes/*.java src/Main/*.java  2>/dev/null

	if [ "$?" == "0" ]; then 
		echo -e "${orangeColour}[!] Compiled Successfully!${endColour}"
		echo
		echo -e "${turquoiseColour}[~] Executing it!\n${endColour}"
	else
		echo -e "${redColour}[X] An error occurred while compilation process."
	fi

	# Move the files where corresponds
	mv "$javanet_path/src/Main/Main.class" "$javanet_path/bin/Main"
	mv "$javanet_path/src/Classes/"*class "$javanet_path/bin/Classes"


}

# For executing the Java program
javat_exec (){

	main_path="$default_path/javanet/bin/Main"
	cd "$main_path" || exit

	#java -cp ".:../Classes:lib/opencsv-5.7.1.jar" Main
	java Main 2>/dev/null

}
