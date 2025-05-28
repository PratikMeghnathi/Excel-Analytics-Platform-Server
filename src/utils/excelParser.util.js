import xlsx from 'xlsx';

const determineColumnType = (values) => {
    const filteredValues = values.filter(value => value !== null && value !== undefined && value !== '');
    if (filteredValues.length === 0) return 'string';

    let typeCounts = { numeric: 0, string: 0, boolean: 0, date: 0 };

    for (const value of filteredValues) {
        if (typeof value === 'number') {
            typeCounts.numeric++;
            continue;
        }

        if (typeof value === 'boolean' || value === 'TRUE' || value === 'FALSE' || value === 'True' || value === 'False' || value === 'true' || value === 'false') {
            typeCounts.boolean++;
            continue;
        }

        if (typeof value === 'string') {
            if (!isNaN(value) && !isNaN(parseFloat(value))) {
                typeCounts.numeric++;
                continue;
            }

            try {
                const date = new Date(value);
                if (!isNaN(date.getTime()) &&
                    (value.includes('-') || value.includes('/') ||
                        value.includes(',') || value.match(/[a-zA-Z]/))) {
                    typeCounts.date++;
                    continue;
                }
            } catch (e) {
                console.log(e)
            }
            typeCounts.string++;
        }
    }

    const total = Object.values(typeCounts).reduce((sum, count) => sum + count, 0);
    const typePercentages = {};
    for (const type in typeCounts) {
        typePercentages[type] = (typeCounts[type] / total) * 100;
    }

    const THRESHOLD = 90;

    if (typePercentages.numeric >= THRESHOLD) return 'numeric';
    if (typePercentages.boolean >= THRESHOLD) return 'boolean';
    if (typePercentages.date >= THRESHOLD) return 'date';
    if (typePercentages.string >= THRESHOLD) return 'string';

    const dominantType = Object.keys(typePercentages).reduce((a, b) =>
        typePercentages[a] > typePercentages[b] ? a : b
    );

    // console.log(`Mixed column type detected: ${dominantType} (${typePercentages[dominantType].toFixed(2)}%)`);
    return dominantType;
};


const parseExcelFile = (filePath) => {
    try {
        const workbook = xlsx.readFile(filePath, { cellDates: true });
        const sheetNames = workbook.SheetNames;
        const allSheetsData = {};


        sheetNames.forEach(sheetName => {
            const worksheet = workbook.Sheets[sheetName];
            const jsonData = xlsx.utils.sheet_to_json(worksheet, {
                header: 1,
                raw: true,
                dateNF: 'yyyy-mm-dd'
            });

            if (!jsonData || jsonData.length === 0) {
                allSheetsData[sheetName] = {
                    headers: [],
                    rows: [],
                    columnTypes: [],
                    totalRows: 0
                };
                return;
            }

            const headers = jsonData[0].map(header =>
                header ? String(header).trim() : `Column${Math.random().toString(36).substring(2, 7)}`
            );

            const rows = jsonData.slice(1);
            const columnTypes = headers.map((header, index) => {
                const values = rows.map(row => row[index]).filter(val => val !== undefined);
                return {
                    name: header,
                    type: determineColumnType(values)
                };
            });

            allSheetsData[sheetName] = {
                headers,
                rows,
                columnTypes,
                totalRows: rows.length
            };
        });

        return {
            sheetNames,
            sheets: allSheetsData,
            totalSheets: sheetNames.length
        };
    } catch (error) {
        throw new Error(`Failed to parse Excel file: ${error.message}`);
    }
};

export default parseExcelFile;
