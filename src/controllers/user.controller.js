import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.models.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefereshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    console.log("Generate access and Refresh Token (user) ", user);

    const accessToken = user.generateAccessToken();
    console.log(
      "Generate access and Refresh Token (accessToken) ",
      accessToken
    );
    const refreshToken = user.generateRefreshToken();
    console.log(
      "Generate access and Refresh Token (refreshToken) ",
      refreshToken
    );

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating referesh and access token"
    );
  }
};

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

  console.log(`Existed User ${existedUser}`);

  if (existedUser) {
    throw new ApiError(409, "User with username or email already exists");
  }
  //Getting error here
  // console.log(`Checking require fields - ${req.files.avatar[0]}`);
  if (!req.files || !req.files.avatar) {
    throw new ApiError(400, "Avatar file is missing");
  }

  // Then check if the avatar array has at least one element
  if (req.files.avatar.length === 0) {
    throw new ApiError(400, "Avatar file is missing");
  }
  const avatarLocalPath = req.files.avatar[0].path;
  // const coverImagelocalPath = req.files?.coverImage[0]?.path;
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

const loginUser = asyncHandler(async (req, res) => {
  //req body -> data
  // username or email
  // find the user
  // password check
  // access and refresh token
  // send cookie

  const { email, username, password } = req.body;
  if (!email) throw new ApiError(400, "username or email is required");
  const user = await User.findOne({
    $or: [{ username }, { email }],
  });
  console.log(
    ` Email - ${email} , Username - ${username} , Password - ${password}`
  );
  if (!email) throw new ApiError(404, "User does not exist");

  const isPasswordValid = await user.isPasswordCorrect(password);

  console.log(`isPasswordValid - ${isPasswordValid}`);

  if (!isPasswordValid) throw new ApiError(401, "Password incorrect");

  const { accessToken, refreshToken } = await generateAccessAndRefereshTokens(
    user._id
  );

  const loggedInUser = await User.findById(user._id).select(
    -password - refreshToken
  );
  const options = { httpOnly: true, secure: true };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "User logged In Successfully"
      )
    );
});

const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(req.user._id, {
    $set: { refreshToken: undefined },
  });

  const options = { httpOnly: true, secure: true };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  try {
    const incomingRefreshToken =
      req.cookies.refreshToken || req.body.refreshToken;

    if (!incomingRefreshToken) throw new ApiError(401, "Inauthorized request");
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );
    const user = await User.findById(decodedToken?._id);
    if (!user) throw new ApiError(401, "Invalid refresh token");

    if (incomingRefreshToken !== user?.refreshToken)
      throw new ApiError(401, "Refresh token is expired or used");

    const options = {
      httpOnly: true,
      secure: true,
    };

    const { accessToken, newRefreshToken } =
      await generateAccessAndRefereshTokens(user._id);

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access token refreshed successfully"
        )
      );
  } catch (error) {
    throw new ApiError(401, error?.message || "Invalid refresh token");
  }
});

export { registerUser, loginUser, logoutUser, refreshAccessToken };
