# Create a directory for the libraries
mkdir libs
cd libs

# Clone into the 'libs' directory
git clone https://github.com/ProtonVPN/python-proton-vpn-api-core.git

# remove the .gitmodules file
rm python-proton-vpn-api-core/.gitmodules

# Navigate into the proton-vpn-api-core directory (after potentially modifying .gitmodules)
cd python-proton-vpn-api-core
# Install it (and its public dependencies)
pip install .
