#include <stdlib.h>
#include <math.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>

/**
 * Definition of stringToDouble.
 * 
 * Converts a string to a double.
 */
double stringToDouble(const std::string& s)
{
	std::istringstream i(s);
	double x;
	if (!(i >> x))
		return 0;
	return x;
}
/* END definition of function stringToDouble */

/**
 * Definition of parseToDoubles.
 * 
 * Converts a string of comma-separated values to a vector of doubles.
 */
std::vector<double> parseToDoubles(std::string line)
{
	std::vector<double> result;
	std::stringstream lineStream(line);
	std::string cell;

	// Skipping first element; it's a header
	std::getline(lineStream, cell, ',');

	while(std::getline(lineStream, cell, ','))
    {
		double val = stringToDouble(cell);

        // Round value to 4 decimals.
		double new_val = std::ceil(val * 1000.0) / 1000.0;

		if (new_val == 0 && val != 0) {
			std::cout << "zero" << std::endl;
		}

        result.push_back(new_val);
    }

	return result;
}
/* END definition parseToDoubles */