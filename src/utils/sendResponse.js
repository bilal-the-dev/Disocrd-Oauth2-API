exports.sendResponse = (req, res, fieldName, data) => {
  const {
    discordUser,
    query: { fields },
  } = req;

  const fieldArray = fields?.split(",");

  if (fieldArray?.includes("user")) data = { discordUser, [fieldName]: data };

  res.send({
    status: "success",
    data,
  });
};
