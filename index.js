function TestUserInput()
{
    const selectedRegex = document.querySelector('#regexSelector').value;
    const userInput = document.querySelector('#userInput').value;
    const result = GetRegexValidator(selectedRegex, userInput);
    const resultBox = document.querySelector('#resultBox');
    if (result)
    {
        resultBox.innerHTML = 'True';
        resultBox.classList.remove('p-negative');
        resultBox.classList.add('p-positive');
    }
    else
    {
        resultBox.innerHTML = 'False';
        resultBox.classList.add('p-negative');
        resultBox.classList.remove('p-positive');

    }
}

function GetRegexValidator(selectedRegex, userInput)
{
    let returnValue;
    const dict = {
        wholeNum: (value) => { returnValue = ValidateWholeNumber(value) },
        decimalNum: (value) => { returnValue = ValidateDecimalNumber(value) },
        wholeAndDecNum: (value) => { returnValue = ValidateWholeAndDecimalNumbers(value) },
        negPosWholeAndDecNum: (value) => { returnValue = ValidateNegativePositiveWholeAndDecimalNumber(value) },
        wholeDecFraction: (value) => { returnValue = ValidateWholeDecimalAndFractionNumbers(value) },
        alphaNumNoSpace: (value) => { returnValue = ValidateAlphanumericWithoutSpace(value) },
        alphaNumWithSpace: (value) => { returnValue = ValidateAlphanumericWithSpace(value) },
        commonEmail: (value) => { returnValue = ValidateCommonEmail(value) },
        unCommonEmail: (value) => { returnValue = ValidateUncommonEmail(value) },
        complexPassword: (value) => { returnValue = ValidateComplexPassword(value) },
        moderatePassword: (value) => { returnValue = ValidateModeratePassword(value) },
        userName: (value) => { returnValue = ValidateUsername(value) },
        v4Ip: (value) => { returnValue = ValidateIPV4Address(value) },
        v6Ip: (value) => { returnValue = ValidateIPV6Address(value) },
        v4orV6Ip: (value) => { returnValue = ValidateIPV4OrV6Address(value) },
        ymd: (value) => { returnValue = ValidateYearMonthDayDate(value) },
        dmy: (value) => { returnValue = ValidateDayMonthYearDate(value) },
        dabvmy: (value) => { returnValue = ValidateDayMonthAbvYearDate(value) },
        Time12Hr: (value) => { returnValue = Validate12hrTimeFormat(value) },
        Time24Hr: (value) => { returnValue = Validate24HrTimeFormat(value) },
        inlineJs: (value) => { returnValue = ValidateInlineJSHandler(value) },
        inlineWithElement: (value) => { returnValue = ValidateInlineJSHandlerWithElement(value) },
        slug: (value) => { returnValue = ValidateSlug(value) },
        dupes: (value) => { returnValue = MatchDuplicates(value) },
        phoneNumbers: (value) => { returnValue = ValidatePhoneNumbers(value) },
        filePathWithExt: (value) => { returnValue = ValidateFilePathWithNameAndExtension(value) },
        filePathOptionalExt: (value) => { returnValue = ValidateFilePathWithOptionalNameAndExtension(value) }
    }
    dict[selectedRegex](userInput)
    return returnValue;
}


//Numbers
function ValidateWholeNumber(userInput)
{
    const regex = /^\d+$/;
    return regex.test(userInput);
}

function ValidateDecimalNumber(userInput)
{
    const regex = /^\d*\.\d+$/;
    return regex.test(userInput);
}

function ValidateWholeAndDecimalNumbers(userInput)
{
    const regex = /^\d*(\.\d+)?$/;
    return regex.test(userInput)
}

function ValidateNegativePositiveWholeAndDecimalNumber(userInput)
{
    const regex = /^-?\d*(\.\d+)?$/;
    return regex.test(userInput);
}


function ValidateWholeDecimalAndFractionNumbers(userInput)
{
    const regex = /[-]?[0-9]+[,.]?[0-9]*([\/][0-9]+[,.]?[0-9]*)*/;
    return regex.test(userInput)
}

//Alphanumeric
function ValidateAlphanumericWithoutSpace(userInput)
{
    const regex = /^[a-zA-Z0-9]*$/;
    return regex.test(userInput)
}

function ValidateAlphanumericWithSpace(userInput)
{
    const regex = /^[a-zA-Z0-9 ]*$/;
    return regex.test(userInput)
}

//Emails
function ValidateCommonEmail(userInput)
{
    const regex = /^([a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})*$/;
    return regex.test(userInput)
}

function ValidateUncommonEmail(userInput)
{
    const regex = /^([a-z0-9_\.\+-]+)@([\da-z\.-]+)\.([a-z\.]{2,6})$/;
    return regex.test(userInput)
}

//Passwords
function ValidateComplexPassword(userInput)
{
    const regex = /(?=(.*[0-9]))(?=.*[\!@#$%^&*()\\[\]{}\-_+=~`|:;"'<>,./?])(?=.*[a-z])(?=(.*[A-Z]))(?=(.*)).{8,}/;
    return regex.test(userInput)
}

function ValidateModeratePassword(userInput)
{
    const regex = /(?=(.*[0-9]))((?=.*[A-Za-z0-9])(?=.*[A-Z])(?=.*[a-z]))^.{8,}$/;
    return regex.test(userInput)
}

//UserName
function ValidateUsername(userInput)
{
    const regex = /^[a-z0-9_-]{3,16}$/;
    return regex.test(userInput)
}

//URLs
function ValidateURLWithHTTPS(userInput)
{
    const regex = /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#()?&//=]*)/;
    return regex.test(userInput)
}

function ValidateURLWithOptionalHTTPS(userInput)
{
    const regex = /(https?:\/\/)?(www\.)?[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)/;
    return regex.test(userInput)
}

//IPs
function ValidateIPV4Address(userInput)
{
    const regex = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;
    return regex.test(userInput)
}

function ValidateIPV6Address(userInput)
{
    const regex = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/;
    return regex.test(userInput)
}

function ValidateIPV4OrV6Address(userInput)
{
    const regex = /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))/;
    return regex.test(userInput)
}

//Dates
function ValidateYearMonthDayDate(userInput)
{
    const regex = /([12]\d{3}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01]))/;
    return regex.test(userInput)
}

function ValidateDayMonthYearDate(userInput)
{
    const regex = /^(?:(?:31(\/|-|\.)(?:0?[13578]|1[02]))\1|(?:(?:29|30)(\/|-|\.)(?:0?[1,3-9]|1[0-2])\2))(?:(?:1[6-9]|[2-9]\d)?\d{2})$|^(?:29(\/|-|\.)0?2\3(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))$|^(?:0?[1-9]|1\d|2[0-8])(\/|-|\.)(?:(?:0?[1-9])|(?:1[0-2]))\4(?:(?:1[6-9]|[2-9]\d)?\d{2})$/;
    return regex.test(userInput)
}

function ValidateDayMonthAbvYearDate(userInput)
{
    const regex = /^(?:(?:31(\/|-|\.)(?:0?[13578]|1[02]|(?:Jan|Mar|May|Jul|Aug|Oct|Dec)))\1|(?:(?:29|30)(\/|-|\.)(?:0?[1,3-9]|1[0-2]|(?:Jan|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec))\2))(?:(?:1[6-9]|[2-9]\d)?\d{2})$|^(?:29(\/|-|\.)(?:0?2|(?:Feb))\3(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))$|^(?:0?[1-9]|1\d|2[0-8])(\/|-|\.)(?:(?:0?[1-9]|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep))|(?:1[0-2]|(?:Oct|Nov|Dec)))\4(?:(?:1[6-9]|[2-9]\d)?\d{2})$/;
    return regex.test(userInput)
}

//Time
function Validate12hrTimeFormat(userInput)
{
    const regex = /^(0?[1-9]|1[0-2]):[0-5][0-9]$/;
    return regex.test(userInput)
}

function Validate24HrTimeFormat(userInput)
{
    const regex = /^([0-9]|0[0-9]|1[0-9]|2[0-3]):[0-5][0-9]$/;
    return regex.test(userInput)
}

//HTMLTags
function ValidateHTMLTag(userInput)
{
    const regex = /<\/?[\w\s]*>|<.+[\W]>/;
    return regex.test(userInput)
}

//JSHandlers
function ValidateInlineJSHandler(userInput)
{
    const regex = /\bon\w+=\S+(?=.*>)/;
    return regex.test(userInput)
}

function ValidateInlineJSHandlerWithElement(userInput)
{
    const regex = /(?:<[^>]+\s)(on\S+)=["']?((?:.(?!["']?\s+(?:\S+)=|[>"']))+.)["']?/;
    return regex.test(userInput)
}

//Slug
function ValidateSlug(userInput)
{
    const regex = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
    return regex.test(userInput)
}

//Match Duplicates
function MatchDuplicates(userInput)
{
    const regex = /(\b\w+\b)(?=.*\b\1\b)/;
    return regex.test(userInput)
}

//Phone Numbers
function ValidatePhoneNumbers(userInput)
{
    const regex = /^(?:(?:\(?(?:00|\+)([1-4]\d\d|[1-9]\d?)\)?)?[\-\.\ \\\/]?)?((?:\(?\d{1,}\)?[\-\.\ \\\/]?){0,})(?:[\-\.\ \\\/]?(?:#|ext\.?|extension|x)[\-\.\ \\\/]?(\d+))?$/;
    return regex.test(userInput)
}

//File Paths
function ValidateFilePathWithNameAndExtension(userInput)
{
    const regex = /((\/|\\|\/\/|https?:\\\\|https?:\/\/)[a-z0-9 _@\-^!#$%&+={}.\/\\\[\]]+)+\.[a-z]+$/;
    return regex.test(userInput)
}

function ValidateFilePathWithOptionalNameAndExtension(userInput)
{
    const regex = /^(.+)\/([^/]+)$/;
    return regex.test(userInput)
}

function ValidateFileNameWithExtension(userInput)
{
    const regex = /^[\w,\s-]+\.[A-Za-z]{3}$/;
    return regex.test(userInput)
}
