import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.models.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";

const registerUser = asyncHandler(async (req, res) => {
  // Get user from frontend
  // Validation - not empty
  // Check if user is already exists: username, email
  // Check for images, check for avtar
  // Upload to cloudinary, avatar
  // Create user obj - create entry in db
  // Remove password and refresh token field from response
  // Check for user creation
  // return response

  const { fullName, email, username, password } = req.body;
  console.log("Body of the reques", req.body);
  console.log("email: ", email);

  if (
    [fullName, email, username, password].some((field) => field?.trim() === "")
  ) {
    throw new ApiError(400, "All fields are required");
  }

  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(409, "User with username or email already exists");
  }
  console.log("Request Body", req.files);
  const avatarLocalPath = req.files?.avatar[0]?.path;
  //const coverImagelocalPath = req.files?.coverImage[0]?.path;
  console.log("avatarLocalPath ->", avatarLocalPath);
  if (!avatarLocalPath)
    throw new ApiError(400, "Avatar Local Path is required");

  let coverImagelocalPath;
  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  ) {
    coverImagelocalPath = req.files.coverImage[0].path;
  }

  //Getting error here
  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImagelocalPath);
  console.log("avatar ->", avatar);
  if (!avatar) throw new ApiError(400, "Avatar file is required");

  const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase(),
  });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );
  if (!createdUser)
    throw new ApiError(500, "Something went wrong wwhile registering the user");

  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User registered successfully"));
});

export { registerUser };
