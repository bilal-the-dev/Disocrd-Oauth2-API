const catchAsync = require("../utils/catchAsync");
const { fetchUserGuildsOauth } = require("../utils/discordOauth");
const { sendResponse } = require("../utils/sendResponse");

exports.getCurrentUser = catchAsync(async (req, res, next) => {
  sendResponse(req, res, "user", req.discordUser);
});

exports.getCurrentUserGuilds = catchAsync(async (req, res, next) => {
  let guilds = await fetchUserGuildsOauth(req.dbUser.accessToken);

  const ADMIN_BIT = 0x0000000000000008;

  if (req.query.adminOnly == "true")
    guilds = guilds.filter((g) => (g.permissions & ADMIN_BIT) == ADMIN_BIT);

  sendResponse(req, res, "guilds", guilds);
});
