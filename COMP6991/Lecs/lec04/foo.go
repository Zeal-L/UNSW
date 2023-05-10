f, err := os.Open("filename.ext")
if err != nil {
	log.Fatal(err)
}
// do something with the open *File f