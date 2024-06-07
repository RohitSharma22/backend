import { v2 as cloudinary } from "cloudinary";
import fs, { fstatSync } from "fs";

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const uploadOnCloudinary = async (localFilePath) => {
  try {
    console.log("Inside upload on cloudinary");
    if (!localFilePath) return null;
    // Upload the file on cloudinary
    const response = await cloudinary.uploader.upload(localFilePath, {
      resource_type: "auto",
    });
    console.log("Cloudinary Response ->", response);

    //File has been uploaded successfull
    // console.log("File is uploaded on cloudinary", response.url);
    fs.unlinkSync(localFilePath);
    return response;
  } catch (error) {
    console.log("Error in uploadCloudinary", error);
    fs.unlinkSync(localFilePath); // remove the locally saved temprory file as the upload operation got failed.
    return null;
  }
};

export { uploadOnCloudinary };
