// Description: A simple Express.js application for a football club management system
const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const app = express();
const session = require('express-session');
const flash = require('connect-flash');
const multer = require('multer');
const path = require('path');
const router = express.Router();
const fs = require('fs');
const ejs = require('ejs');
const port = 3000;
const stripe = require('stripe')('sk_test_51Rbd3n2KqbnLclsGFpqTIXmrehW6pmXxefcdmZBHwGLrAWTZyUB8BiQIJzQ74ikAGWsXqg4n1ybEeUZ78tRs4Fwt0042Et2pjl');
const stripeStore = require('stripe')('sk_test_51Rknd72E9KtrAGClRgPCeq56TxLd5eqn5f6KOcAj5BhYpwLZVMvYrCHKU4UTXLHnHsCAxAk4G414XzCEuBjoygyl00kbmAsFWX');//sayhan store secret key
const bcrypt = require('bcrypt'); //  bcrypt is required at the top of my file
const saltRounds = 10;
console.log("app2.js is running");


app.use(express.urlencoded({ extended: true }));
app.use(express.json());


app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});


let connection;

function handleDisconnect() {
  connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'footballclub'
  });

  connection.connect(err => {
    if (err) {
      console.error('Error connecting to MySQL:', err);
      setTimeout(handleDisconnect, 2000); // Retry after 2s
    } else {
      console.log('Connected to MySQL database');
    }
  });

  connection.on('error', err => {
    console.error('MySQL error', err);
    if (err.code === 'PROTOCOL_CONNECTION_LOST') {
      handleDisconnect(); // Reconnect on lost connection
    } else {
      throw err;
    }
  });
}

handleDisconnect();


app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true
}));


app.use(flash());

app.use((req, res, next) => {
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  next();
});

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/images');
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + ext);
  }
});

const upload = multer({ storage: storage });

// Routes


app.get('/', (req, res) => {
  connection.query('SELECT * FROM event ORDER BY EventDate ASC', (err, events) => {
    if (err) {
      console.error('Error fetching events:', err);
      return res.status(500).send('Error loading homepage');
    }
    res.render('homepage', { events }); // make sure to update the view file name if needed
  });
});
//@MahendraTheCurryMan





//kamali
// Retrieve restaurant items (UPDATED - exclude removed items)
app.get('/restaurant', (req, res) => {
  const member = req.session.member;
  const message = req.query.message;//retrieves optional messages like success messages frm ?message=Item+Added...

  if (!member) {
    return res.redirect('/login');
  }

  // FIXED SQL: Filter by is_active status instead of price/removed
  const sql = `
    SELECT ItemID, Name, Description, Price, Image 
    FROM restaurantitem 
    WHERE is_active = 1
    ORDER BY Name ASC
  `;

  connection.query(sql, (err, results) => {
    if (err) {
      console.error('Error retrieving restaurant items:', err);
      return res.status(500).send('Error retrieving restaurant items.');
    }

    console.log(`Found ${results.length} active restaurant items`);
    
    res.render('restaurant', { 
      foodItems: results, 
      member,
      message: message
    });
  });
});

// Alternative: If you want to keep both filters (active AND price > 0)
app.get('/restaurant-alternative', (req, res) => {
  const member = req.session.member;
  const message = req.query.message;

  if (!member) {
    return res.redirect('/login');
  }

  // Combined filters: active items with price > 0
  const sql = `
    SELECT ItemID, Name, Description, Price, Image 
    FROM restaurantitem 
    WHERE is_active = 1 
      AND Price > 0
    ORDER BY Name ASC
  `;

  connection.query(sql, (err, results) => {
    if (err) {
      console.error('Error retrieving restaurant items:', err);
      return res.status(500).send('Error retrieving restaurant items.');
    }

    console.log(`Found ${results.length} active restaurant items with price > 0`);
    
    res.render('restaurant', { 
      foodItems: results, 
      member,
      message: message
    });
  });
});



// NEW: Add restaurant item to cart (SIMPLE VERSION )
app.post('/restaurant/add-to-cart/:id', (req, res) => {
  const itemId = req.params.id;
  const quantity = parseInt(req.body.quantity) || 1;

  if (!req.session.member) {
    return res.redirect('/login');
  }

  const sql = 'SELECT * FROM restaurantitem WHERE ItemID = ?';
  connection.query(sql, [itemId], (error, results) => {
    if (error) {
      console.error('Error finding restaurant item:', error);
      return res.status(500).send('Error adding to cart');
    }

    if (results.length === 0) {
      return res.status(404).send('Restaurant item not found');
    }

    const item = results[0];

    if (!req.session.cart) {
      req.session.cart = [];
    }

    // Check if this restaurant item is already in cart
    const existing = req.session.cart.find(i => 
      i.id === item.ItemID && i.type === 'restaurant'
    );
    
    if (existing) {
      existing.quantity += quantity;
    } else {
      req.session.cart.push({
        id: item.ItemID,
        type: 'restaurant', // Mark as restaurant item
        name: item.Name,
        price: parseFloat(item.Price),
        image: item.Image,
        description: item.Description,
        quantity: quantity
      });
    }

    console.log('Restaurant item added to cart:', item.Name, 'x' + quantity);
    
    // Simple redirect to cart 
    res.redirect('/restaurant?message=Food item added to cart successfully');
  });
});

// NEW: Remove restaurant item from cart 
app.post('/restaurant/remove-from-cart/:id', (req, res) => {
  if (!req.session.cart) return res.redirect('/cart');
  
  const itemId = parseInt(req.params.id);
  req.session.cart = req.session.cart.filter(item => 
    !(item.type === 'restaurant' && item.id === itemId)
  );
  
  res.redirect('/cart');
});

//kamaliadmin
/// Routes for Admin Restaurant 

// GET all restaurant items - Updated to handle showAll and message parameters
app.get('/admin/items', (req, res) => {
    if (!req.session.admin) return res.redirect('/login');
    
    const showAll = req.query.showAll === 'true';
    const showForceDelete = req.query.showForceDelete;
    
    let sql = 'SELECT * FROM restaurantitem';
    if (!showAll) {
        sql += ' WHERE is_active = TRUE OR is_active IS NULL';
    }
    sql += ' ORDER BY Name ASC';
    
    connection.query(sql, (error, results) => {
        if (error) {
            console.error("Error fetching restaurant items:", error);
            return res.status(500).send('Error fetching restaurant items');
        }
        

        res.render('adminItemList', {
            items: results || [],        
            admin: req.session.admin,
            showAll: showAll,
            message: req.query.message || null,
            showForceDelete: showForceDelete || null
        });
    });
});


// GET route: show the Add Restaurant Item form
app.get('/admin/items/add', (req, res) => {
  if (!req.session.admin) return res.redirect('/login');
  res.render('adminItemAdd', {
    admin: req.session.admin
  });
});

// POST route: handle form submission with image upload using multer
app.post('/admin/items/add', upload.single('Image'), (req, res) => {
  if (!req.session.admin) return res.redirect('/login');
  const { Name, Description, Price } = req.body;
  const imagePath = req.file ? '/images/' + req.file.filename : null;
  
  const sql = 'INSERT INTO restaurantitem (Name, Description, Price, Image, is_active) VALUES (?, ?, ?, ?, TRUE)';
  connection.query(sql, [Name, Description, Price, imagePath], (error, results) => {
    if (error) {
      console.error("Error adding restaurant item:", error);
      return res.status(500).send('Error adding restaurant item');
    }
    
    const successMessage = encodeURIComponent('Restaurant item added successfully');
    res.redirect(`/admin/items?message=${successMessage}`);
  });
});

// Update restaurant item page
app.get('/admin/items/edit/:id', (req, res) => {
  const itemId = req.params.id;
  const sql = 'SELECT * FROM restaurantitem WHERE ItemID = ?';
  connection.query(sql, [itemId], (error, results) => {
    if (error) {
      console.error('Database query error:', error.message);
      return res.status(500).send('Error retrieving item by ID');
    }
    if (results.length > 0) {
      res.render('adminItemEdit', { item: results[0], admin: req.session.admin });
    } else {
      res.status(404).send('Restaurant item not found');
    }
  });
});

// Update restaurant item 
app.post('/admin/items/edit/:id', upload.single('Image'), (req, res) => {
  const itemId = req.params.id;
  const { Name, Description, Price } = req.body;
  
  // Enhanced debugging
  console.log('=== EDIT RESTAURANT ITEM DEBUG ===');
  console.log('Request body:', req.body);
  console.log('Item ID:', itemId);
  console.log('Name received:', Name);
  console.log('Description received:', Description);
  console.log('Price received:', Price);
  
  // Validate required fields
  if (!Name || !Price) {
    console.error('Missing required fields:', {
      Name: !!Name,
      Price: !!Price
    });
    return res.status(400).send('Missing required fields');
  }
  
  const imagePath = req.file ? '/images/' + req.file.filename : null;
  let sql, params;
  
  if (imagePath) {
    sql = 'UPDATE restaurantitem SET Name = ?, Description = ?, Price = ?, Image = ? WHERE ItemID = ?';
    params = [Name, Description, Price, imagePath, itemId];
  } else {
    sql = 'UPDATE restaurantitem SET Name = ?, Description = ?, Price = ? WHERE ItemID = ?';
    params = [Name, Description, Price, itemId];
  }
  
  console.log('SQL:', sql);
  console.log('Params:', params);
  
  connection.query(sql, params, (error, results) => {
    if (error) {
      console.error('Database error:', error);
      return res.status(500).send('Error updating restaurant item: ' + error.message);
    }
    
    console.log('Update results:', results);
    console.log('Affected rows:', results.affectedRows);
    console.log('Changed rows:', results.changedRows);
    
    // Verify the update by querying the item
    const verifySql = 'SELECT * FROM restaurantitem WHERE ItemID = ?';
    connection.query(verifySql, [itemId], (verifyError, verifyResults) => {
      if (verifyError) {
        console.error('Verification error:', verifyError);
      } else {
        console.log('Updated item:', verifyResults[0]);
      }
      
      const successMessage = encodeURIComponent('Restaurant item updated successfully');
      res.redirect(`/admin/items?message=${successMessage}`);
    });
  });
});

// List restaurant item (make active/visible)
app.get('/listRestaurantItem/:id', (req, res) => {
  if (!req.session.admin) return res.redirect('/login');
  
  const itemId = req.params.id;
  const sql = 'UPDATE restaurantitem SET is_active = TRUE WHERE ItemID = ?';
  
  connection.query(sql, [itemId], (error, results) => {
    if (error) {
      console.error("Error listing restaurant item:", error);
      return res.status(500).send('Error listing restaurant item');
    }
    
    const successMessage = encodeURIComponent('Restaurant item successfully listed');
    res.redirect(`/admin/items?message=${successMessage}`);
  });
});

// Unlist restaurant item (make inactive/hidden but keep in database)
app.get('/unlistRestaurantItem/:id', (req, res) => {
  if (!req.session.admin) return res.redirect('/login');
  
  const itemId = req.params.id;
  
  // Mark item as unlisted instead of deleting
  const sql = 'UPDATE restaurantitem SET is_active = FALSE WHERE ItemID = ?';
  
  connection.query(sql, [itemId], (error, results) => {
    if (error) {
      console.error("Error unlisting restaurant item:", error);
      return res.status(500).send('Error unlisting restaurant item');
    }
    
    const successMessage = encodeURIComponent('Restaurant item unlisted (order history preserved)');
    res.redirect(`/admin/items?message=${successMessage}`);
  });
});

// DELETE restaurant item completely from database (ENHANCED VERSION)
app.post('/admin/items/delete/:id', (req, res) => {
  if (!req.session.admin) return res.redirect('/login');
  
  const itemId = req.params.id;
  const forceDelete = req.body.forceDelete === 'true'; // Check if force delete was requested
  
  console.log(`Admin attempting to delete restaurant item ${itemId}, forceDelete: ${forceDelete}`);
  
  if (forceDelete) {
    // FORCE DELETE: Remove item regardless of order history
    console.log(` FORCE DELETE requested for restaurant item ${itemId}`);
    
    // Start transaction to ensure data consistency
    connection.beginTransaction((err) => {
      if (err) {
        console.error('Transaction start error:', err);
        const errorMessage = encodeURIComponent('Failed to start deletion process');
        return res.redirect(`/admin/items?message=${errorMessage}`);
      }

      // Step 1: Delete all restaurant bill records for this item
      const deleteBillsSql = 'DELETE FROM restaurantbill WHERE fk_ItemID = ?';
      
      connection.query(deleteBillsSql, [itemId], (billErr, billResult) => {
        if (billErr) {
          return connection.rollback(() => {
            console.error('Error deleting restaurant bill records:', billErr);
            const errorMessage = encodeURIComponent('Failed to delete order records');
            res.redirect(`/admin/items?message=${errorMessage}`);
          });
        }

        console.log(` Deleted ${billResult.affectedRows} restaurant bill records for item ${itemId}`);

        // Step 2: Delete the item itself
        const deleteItemSql = 'DELETE FROM restaurantitem WHERE ItemID = ?';
        
        connection.query(deleteItemSql, [itemId], (itemErr, itemResult) => {
          if (itemErr) {
            return connection.rollback(() => {
              console.error('Error deleting restaurant item:', itemErr);
              const errorMessage = encodeURIComponent('Failed to delete restaurant item');
              res.redirect(`/admin/items?message=${errorMessage}`);
            });
          }

          if (itemResult.affectedRows === 0) {
            return connection.rollback(() => {
              const notFoundMessage = encodeURIComponent('Restaurant item not found');
              res.redirect(`/admin/items?message=${notFoundMessage}`);
            });
          }

          // Commit the transaction
          connection.commit((commitErr) => {
            if (commitErr) {
              return connection.rollback(() => {
                console.error('Transaction commit error:', commitErr);
                const errorMessage = encodeURIComponent('Failed to complete deletion');
                res.redirect(`/admin/items?message=${errorMessage}`);
              });
            }

            console.log(` FORCE DELETE completed for restaurant item ${itemId} and all order records`);
            const successMessage = encodeURIComponent('Restaurant item and ALL order history permanently deleted');
            res.redirect(`/admin/items?message=${successMessage}`);
          });
        });
      });
    });

  } else {
    // NORMAL DELETE: Check order history first
    const checkOrdersSql = 'SELECT COUNT(*) as orderCount FROM restaurantbill WHERE fk_ItemID = ?';
    
    connection.query(checkOrdersSql, [itemId], (checkErr, checkResults) => {
      if (checkErr) {
        console.error('Error checking for existing orders:', checkErr);
        const errorMessage = encodeURIComponent('Error checking order history');
        return res.redirect(`/admin/items?message=${errorMessage}`);
      }

      const orderCount = checkResults[0].orderCount;

      if (orderCount > 0) {
        // Item has been ordered - redirect with warning and force delete option
        console.log(` Restaurant item ${itemId} has ${orderCount} orders, offering force delete`);
        const warningMessage = encodeURIComponent(`Cannot delete: ${orderCount} order record(s) exist. Use 'Unlist' to hide, or 'Force Delete' to permanently remove everything.`);
        res.redirect(`/admin/items?message=${warningMessage}&showForceDelete=${itemId}`);
        
      } else {
        // Item has never been ordered - safe to delete normally
        console.log(` Restaurant item ${itemId} has no orders, safe to delete`);
        
        const deleteSql = 'DELETE FROM restaurantitem WHERE ItemID = ?';
        
        connection.query(deleteSql, [itemId], (deleteErr, deleteResult) => {
          if (deleteErr) {
            console.error('Error deleting restaurant item:', deleteErr);
            const errorMessage = encodeURIComponent('Failed to delete restaurant item');
            return res.redirect(`/admin/items?message=${errorMessage}`);
          }
          
          if (deleteResult.affectedRows === 0) {
            const notFoundMessage = encodeURIComponent('Restaurant item not found');
            return res.redirect(`/admin/items?message=${notFoundMessage}`);
          }
          
          console.log(` Restaurant item ${itemId} deleted (no order history)`);
          const successMessage = encodeURIComponent('Restaurant item permanently deleted successfully');
          res.redirect(`/admin/items?message=${successMessage}`);
        });
      }
    });
  }
});

// Checkout success page (KEEP - but make sure it doesn't conflict with your existing one)
app.get('/success', (req, res) => {
  res.render('checkoutsuccess', {
    member: req.session.member
  });
});
//kamali




function isPasswordStrong(password) {
  const strongRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
  return strongRegex.test(password);
}


app.get('/signup', (req, res) => {
  res.render('signup', {
    error: req.flash('error'),
    success: req.flash('success')
  });
});

function validateRegistration(req) {
  const { name, email, password, phone } = req.body;

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (!name || !email || !password || !phone) {
    return 'All fields are required';
  }

  if (!emailRegex.test(email)) {
    return 'Please enter a valid email address';
  }

  if (!isPasswordStrong(password)) {
    return 'Password must be at least 8 characters, include uppercase, lowercase, number, and special character';
  }

  return null;
}


app.post('/signup', (req, res) => {
  const { name, email, password, phone } = req.body;
  const validationError = validateRegistration(req);

  if (validationError) {
    req.flash('error', validationError);
    return res.redirect('/signup');
  }

  const getTierSql = 'SELECT TierID FROM membershiptier WHERE TierName = "Bronze"';

  connection.query(getTierSql, (tierErr, tierResult) => {
    if (tierErr || tierResult.length === 0) {
      req.flash('error', 'Bronze tier not found');
      return res.redirect('/signup');
    }

    const bronzeTierId = tierResult[0].TierID;

    //  Hash password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        req.flash('error', 'Error hashing password');
        return res.redirect('/signup');
      }

      const insertMemberSql = `
        INSERT INTO members (Member_FullName, Member_Email, Member_Password, Member_Phone, fk_TierID, JoinDate)
        VALUES (?, ?, ?, ?, ?, curdate())
      `;

      connection.query(insertMemberSql, [name, email, hashedPassword, phone, bronzeTierId], (dbErr) => {
        if (dbErr) {
          console.error('Insert error:', dbErr);
          req.flash('error', 'Failed to register user');
          return res.redirect('/signup');
        }

        req.flash('success', 'Signup successful!');
        res.redirect('/login'); //  You will see "Cannot GET /login" because it's not defined — that’s expected
      });
    });
  });
});


function isPasswordStrong(password) {
  const strongRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
  return strongRegex.test(password);
}



app.get('/signup', (req, res) => {
  res.render('signup', {
    error: req.flash('error'),
    success: req.flash('success')
  });
});

function validateRegistration(req) {
  const { name, email, password, phone } = req.body;

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (!name || !email || !password || !phone) {
    return 'All fields are required';
  }

  if (!emailRegex.test(email)) {
    return 'Please enter a valid email address';
  }

  if (!isPasswordStrong(password)) {
    return 'Password must be at least 8 characters, include uppercase, lowercase, number, and special character';
  }

  return null;
}




 //Sanjana 

app.get('/login', (req, res) => {
  res.render('login', {
    messages: req.flash('success'),
    errors: req.flash('error')
  });
});



app.post('/login', (req, res) => {
  const { email, password, role } = req.body;

  if (role === 'member') {
    const memberSql = `
      SELECT * FROM members 
      WHERE LOWER(Member_Email) = LOWER(?)
    `;

    connection.query(memberSql, [email], (error, results) => {
      if (error) {
        console.error('Database query error:', error.message);
        return res.status(500).render('login', { error: 'Server error. Please try again.' });
      }

      if (results.length === 0) {
        return res.status(401).render('login', { error: 'Invalid email or password.' });
      }

      const user = results[0];

      bcrypt.compare(password, user.Member_Password, (err, isMatch) => {
        if (err) {
          console.error('bcrypt compare error:', err);
          return res.status(500).render('login', { error: 'Server error. Please try again.' });
        }

        if (isMatch && user.Role && user.Role.toLowerCase() === 'member') {
          req.session.member = user;
          return res.redirect('/Member');
        } else {
          return res.status(401).render('login', { error: 'Invalid email or password.' });
        }
      });
    });

  } else if (role === 'admin') {
    const adminSql = `
      SELECT * FROM clubadmin 
      WHERE LOWER(Admin_Email) = LOWER(?)
    `;

    connection.query(adminSql, [email], (error, results) => {
      if (error) {
        console.error('Database query error:', error.message);
        return res.status(500).render('login', { error: 'Server error. Please try again.' });
      }

      if (results.length === 0) {
        return res.status(401).render('login', { error: 'Invalid admin credentials.' });
      }

      const adminUser = results[0];

      // First, try plain text match
      if (adminUser.Admin_Password === password) {
        req.session.admin = adminUser;
        return res.redirect('/Admin');
      }

      // If not plain text, try bcrypt
      bcrypt.compare(password, adminUser.Admin_Password, (err, isMatch) => {
        if (err) {
          console.error('bcrypt compare error:', err);
          return res.status(500).render('login', { error: 'Server error. Please try again.' });
        }

        if (isMatch && adminUser.Role && adminUser.Role.toLowerCase() === 'admin') {
          req.session.admin = adminUser;
          return res.redirect('/Admin');
        } else {
          return res.status(401).render('login', { error: 'Invalid admin credentials.' });
        }
      });
    });

  } else {
    return res.status(400).render('login', { error: 'Please select a valid role.' });
  }
}); // <-- This closes the app.post

// Middleware to check if member is logged in
const isMemberLoggedIn = (req, res, next) => {
  if (req.session && req.session.member && req.session.member.MemberID) {
    // Member is logged in, proceed to next middleware/route handler
    return next();
  } else {
    // Member is not logged in, redirect to login page
    return res.redirect('/login'); // Based on your routes, the login page is at '/login'
  }
};

 //sanjana

app.get('/logout', (req, res) => {
  req.session.member = null;
  req.flash('success_msg', 'You have logged out successfully!');
  res.redirect('/login');
});

//member profile check for session
app.get('/Member', (req, res) => {
  const email = req.session.member?.Member_Email;
  if (!email) return res.redirect('/login');
  
  // Step 1: Get FRESH member details from database (not session)
  connection.query('SELECT * FROM members WHERE Member_Email = ?', [email], (err, results) => {
    if (err || results.length === 0) {
      return res.status(500).send('User not found');
    }
    const member = results[0];
    const memberId = member.MemberID;
    
    // **CRITICAL FIX**: Update session with fresh database data
    req.session.member = member;
    
    // Step 2: Get pending bookings
    const pendingBookingsSql = `
      SELECT BookingID, BookingDate, StartTime, EndTime, AmountPaid
      FROM Booking
      WHERE fk_MemberID = ? AND Status = 'Pending Payment'
      ORDER BY BookingDate, StartTime
    `;
    connection.query(pendingBookingsSql, [memberId], (pendingErr, pendingResults) => {
      if (pendingErr) return res.status(500).send('Failed to load pending bookings');
      
      // Calculate total outstanding booking amount
      const totalOutstanding = pendingResults.reduce((sum, booking) => {
        return sum + parseFloat(booking.AmountPaid || 0);
      }, 0);
      
      // Step 3: Get total available cashback (non-expired)
      const cashbackSql = `
        SELECT SUM(Amount) as totalCashback
        FROM cashback
        WHERE fk_MemberID = ? AND Cashback_ExpiryDate >= CURDATE() AND Amount > 0
      `;
      connection.query(cashbackSql, [memberId], (cashbackErr, cashbackResults) => {
        if (cashbackErr) return res.status(500).send('Failed to load cashback');
        
        const totalCashback = cashbackResults[0]?.totalCashback || 0;
        
        // Step 4: Get membership tier using FRESH database data
        const tierSql = `SELECT TierName FROM membershiptier WHERE TierID = ?`;
        connection.query(tierSql, [member.fk_TierID], (tierErr, tierResults) => {
          if (tierErr || tierResults.length === 0) {
            return res.status(500).send('Failed to load membership tier');
          }
          const tierName = tierResults[0].TierName;
          
          // Step 5: Get active announcements
          const announcementsSql = `
            SELECT 
              AnnouncementID,
              Title,
              Content,
              CreatedDate,
              Priority,
              ExpiryDate
            FROM announcements
            WHERE Status = 'Active' 
              AND (ExpiryDate IS NULL OR ExpiryDate >= CURDATE())
            ORDER BY Priority DESC, CreatedDate DESC
            LIMIT 3
          `;
          connection.query(announcementsSql, (announcementErr, announcementResults) => {
            if (announcementErr) return res.status(500).send('Failed to load announcements');
            
            // Step 6: Get upcoming events
            connection.query('SELECT * FROM event ORDER BY EventDate ASC', (eventErr, eventResults) => {
              if (eventErr) return res.status(500).send('Failed to load events');
              
              // Send everything to EJS view
              res.render('memberloggedin', {
                member,
                pendingBookings: pendingResults,
                tierName,
                events: eventResults,
                totalOutstanding,
                totalCashback,
                announcements: announcementResults
              });
            });
          });
        });
      });
    });
  });
});

app.get('/member/profile', (req, res) => {
  const member = req.session.member;
  if (!member) return res.redirect('/login');

  // Get member's current tier
  const tierSql = 'SELECT TierName FROM membershiptier WHERE TierID = ?';
  connection.query(tierSql, [member.fk_TierID], (err, tierResults) => {
    if (err) {
      console.error('Error fetching tier:', err);
      return res.status(500).send('Error loading profile');
    }

    const currentTier = tierResults.length > 0 ? tierResults[0].TierName : 'Bronze';
    
    res.render('memberProfile', {
      member,
      currentTier,
      message: req.query.message || null,
      error: req.query.error || null
    });
  });
});

// Update profile information (personal details only)
app.post('/member/profile/update', (req, res) => {
  const member = req.session.member;
  if (!member) return res.redirect('/login');

  const { fullName, email, phone } = req.body;

  // Validate required fields
  if (!fullName || !email) {
    return res.redirect('/member/profile?error=' + encodeURIComponent('Name and email are required'));
  }

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.redirect('/member/profile?error=' + encodeURIComponent('Please enter a valid email address'));
  }

  // Update profile information
  const updateSql = `
    UPDATE members 
    SET Member_FullName = ?, 
        Member_Email = ?, 
        Member_Phone = ?
    WHERE MemberID = ?
  `;

  connection.query(updateSql, [fullName, email, phone, member.MemberID], (err, result) => {
    if (err) {
      console.error('Error updating profile:', err);
      if (err.code === 'ER_DUP_ENTRY') {
        return res.redirect('/member/profile?error=' + encodeURIComponent('Email address already in use'));
      }
      return res.redirect('/member/profile?error=' + encodeURIComponent('Error updating profile'));
    }

    // Update session data
    req.session.member.Member_FullName = fullName;
    req.session.member.Member_Email = email;
    req.session.member.Member_Phone = phone;

    console.log(`Profile updated for member ${member.MemberID}`);
    res.redirect('/member/profile?message=' + encodeURIComponent('Profile updated successfully!'));
  });
});

// Update profile picture
app.post('/member/profile/update-picture', upload.single('profileImage'), (req, res) => {
  const member = req.session.member;
  if (!member) return res.redirect('/login');

  if (!req.file) {
    return res.redirect('/member/profile?error=' + encodeURIComponent('Please select an image file'));
  }

  const profilePicturePath = req.file.filename;

  // Update database with new profile picture
  const updatePictureSql = 'UPDATE members SET Member_ProfilePicture = ? WHERE MemberID = ?';
  
  connection.query(updatePictureSql, [profilePicturePath, member.MemberID], (err, result) => {
    if (err) {
      console.error('Error updating profile picture:', err);
      return res.redirect('/member/profile?error=' + encodeURIComponent('Error updating profile picture'));
    }

    // Update session data
    req.session.member.Member_ProfilePicture = profilePicturePath;

    console.log(`Profile picture updated for member ${member.MemberID}: ${profilePicturePath}`);
    res.redirect('/member/profile?message=' + encodeURIComponent('Profile picture updated successfully!'));
  });
});

// Legacy profile picture upload route (if still needed for navbar)
app.post('/Member/uploadProfilePic', upload.single('profileImage'), (req, res) => {
  const member = req.session.member;
  if (!member) return res.redirect('/login');

  if (!req.file) {
    return res.redirect('/Member?error=' + encodeURIComponent('Please select an image file'));
  }

  const profilePicturePath = req.file.filename;

  const updatePictureSql = 'UPDATE members SET Member_ProfilePicture = ? WHERE MemberID = ?';
  
  connection.query(updatePictureSql, [profilePicturePath, member.MemberID], (err, result) => {
    if (err) {
      console.error('Error updating profile picture:', err);
      return res.redirect('/Member?error=' + encodeURIComponent('Error updating profile picture'));
    }

    req.session.member.Member_ProfilePicture = profilePicturePath;
    console.log(`Profile picture updated via legacy route for member ${member.MemberID}`);
    res.redirect('/Member');
  });
});


 // Sanjana
//sanjana Admin check for session
app.get('/Admin', (req, res) => {
  const email = req.session.admin?.Admin_Email;
  if (!email) return res.redirect('/login');

  connection.query('SELECT * FROM clubadmin WHERE Admin_Email = ?', [email], (err, results) => {
    if (err || results.length === 0) {
      return res.status(500).send('User not found');
    }
    const admin = results[0];
    
    // Get ticket count
    connection.query('SELECT COUNT(*) AS count FROM ticketpurchase', (err1, ticketResult) => {
      const ticketCount = err1 ? 0 : (ticketResult[0]?.count || 0);
      
      // Get announcements count
      connection.query('SELECT COUNT(*) AS count FROM announcements', (err2, announcementResult) => {
        const announcementCount = err2 ? 0 : (announcementResult[0]?.count || 0);
        
        // Get active events count (events with future dates or today)
        connection.query('SELECT COUNT(*) AS count FROM event WHERE EventDate >= CURDATE()', (err3, eventResult) => {
          const eventCount = err3 ? 0 : (eventResult[0]?.count || 0);
          
          // Get total members count
          connection.query('SELECT COUNT(*) AS count FROM members', (err4, memberResult) => {
            const memberCount = err4 ? 0 : (memberResult[0]?.count || 0);
            
            res.render('adminloggedin', { 
              admin, 
              stats: {
                totalMembers: memberCount,
                activeEvents: eventCount, 
                announcements: announcementCount, 
                ticketsSold: ticketCount 
              }
            });
          });
        });
      });
    });
  });
});

// Sanjana
// Route to render profile picture upload form
app.post('/Member/uploadProfilePic', upload.single('profileImage'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('No file uploaded.');
  }

  const filename = req.file.filename;
  const email = req.session.member.Member_Email;

  const sql = 'UPDATE members SET Member_ProfilePicture = ? WHERE Member_Email = ?';
  connection.query(sql, [filename, email], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Database update failed.');
    }

    req.session.member.Member_ProfilePicture = filename;
    res.redirect('/Member');
  });
});



app.get('/Member/announcements', (req, res) => {
  const email = req.session.member?.Member_Email;
  if (!email) return res.redirect('/login');

  // Get member details (for navbar)
  connection.query('SELECT * FROM members WHERE Member_Email = ?', [email], (err, results) => {
    if (err || results.length === 0) {
      return res.status(500).send('User not found');
    }
    const member = results[0];

    // Get all active announcements
    const announcementsSql = `
      SELECT 
        AnnouncementID,
        Title,
        Content,
        CreatedDate,
        Priority,
        ExpiryDate
      FROM announcements
      WHERE Status = 'Active' 
        AND (ExpiryDate IS NULL OR ExpiryDate >= CURDATE())
      ORDER BY Priority DESC, CreatedDate DESC
    `;
    
    connection.query(announcementsSql, (announcementErr, announcements) => {
      if (announcementErr) return res.status(500).send('Failed to load announcements');
      
      res.render('member_announcements', {
        member,
        announcements
      });
    });
  });
});

// Route to render admin profile picture upload form
app.post('/Admin/uploadProfilePic', upload.single('profileImage'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('No file uploaded.');
  }

  const filename = req.file.filename;
  const email = req.session.admin.Admin_Email;

  const sql = 'UPDATE clubadmin SET Admin_ProfilePicture = ? WHERE Admin_Email = ?';
  connection.query(sql, [filename, email], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Database update failed.');
    }

    req.session.admin.Admin_ProfilePicture = filename;
    res.redirect('/Admin');
  });
});
//booking management

const moment = require('moment'); // Make sure you've run: npm install moment

app.get('/Booking', (req, res) => {
  if (!req.session.member) {
    return res.redirect('/login');
  }

  const member = req.session.member;

  // Define date range for current month
  const startDate = moment().startOf('month').format('YYYY-MM-DD');
  const endDate = moment().endOf('month').format('YYYY-MM-DD');

  // Query to fetch booking dates in the current month
  const sql = 'SELECT BookingDate FROM booking WHERE BookingDate BETWEEN ? AND ?';

  connection.query(sql, [startDate, endDate], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Database error');
    }

    // Normalize booking dates to YYYY-MM-DD format
    const bookedDates = results.map(row => moment(row.BookingDate).format('YYYY-MM-DD'));

    // Build calendar array for current month
    const calendar = [];
    const daysInMonth = moment().daysInMonth();
    const firstDayOfMonth = moment().startOf('month');

    for (let i = 0; i < daysInMonth; i++) {
      const dateStr = firstDayOfMonth.clone().add(i, 'days').format('YYYY-MM-DD');
      calendar.push({
        date: dateStr,
        isBooked: bookedDates.includes(dateStr)
      });
    }

    // Render calendar in view
    res.render('memberbooking', {
      member,
      calendar
    });
  });
});

// Handle booking submission
app.post('/Booking', (req, res) => {
  const memberId = req.session.member.MemberID;
  const { bookingDate, timeSlot } = req.body;

  const startTime = timeSlot;
  const endTime = `${parseInt(timeSlot) + 1}:00`;

  // Step 1: Check member's active bookings
  const countSql = `
    SELECT COUNT(*) AS bookingCount 
    FROM Booking 
    WHERE fk_MemberID = ? 
      AND Status IN ('Pending Payment', 'Confirmed')
  `;

  connection.query(countSql, [memberId], (countErr, countResults) => {
    if (countErr) return res.status(500).send('Server error');

    if (countResults[0].bookingCount >= 2) {
      return res.status(403).send('Booking limit reached. Max 2 active bookings.');
    }

    // Step 2: Check slot availability
    const slotCheckSql = `
      SELECT * FROM Booking
      WHERE BookingDate = ? AND StartTime = ? AND Status IN ('Pending Payment', 'Confirmed')
    `;

    connection.query(slotCheckSql, [bookingDate, startTime], (slotErr, slotResults) => {
      if (slotErr) return res.status(500).send('Server error');

      if (slotResults.length > 0) {
        return res.status(409).send('Slot already booked. Choose another.');
      }

      // Step 3: Get tier info
      const tierSql = `
        SELECT mt.TierName
        FROM members m
        JOIN membershiptier mt ON m.fk_TierID = mt.TierID
        WHERE m.MemberID = ?
      `;

      connection.query(tierSql, [memberId], (tierErr, tierResults) => {
        if (tierErr) return res.status(500).send('Server error');

        if (tierResults.length === 0) return res.status(404).send('Tier not found');

        const tierName = tierResults[0].TierName;
        const pricePerHour = tierName === 'Gold' ? 20 :
                             tierName === 'Silver' ? 25 :
                             tierName === 'Bronze' ? 30 : 0;

        const status = 'Pending Payment';
        const amountPaid = pricePerHour;

        // Step 4: Insert booking
        const insertBookingSql = `
          INSERT INTO Booking (fk_MemberID, BookingDate, StartTime, EndTime, Status, AmountPaid)
          VALUES (?, ?, ?, ?, ?, ?)
        `;

        connection.query(
          insertBookingSql,
          [memberId, bookingDate, startTime, endTime, status, amountPaid],
          (insertErr, insertResult) => {
            if (insertErr) return res.status(500).send('Booking failed');

            res.render('memberbookingconfirm', {
              bookingDate,
              startTime,
              endTime,
              tierName,
              amountPaid,
              bookingId: insertResult.insertId
            });
          }
        );
      });
    });
  });
});

app.get('/Booking/confirm-payment', (req, res) => {
  const { bookingId } = req.query;

  if (!bookingId) return res.status(400).send('Booking ID is required');

  const updateSql = `
    UPDATE Booking
    SET Status = 'Confirmed'
    WHERE BookingID = ?
  `;

  connection.query(updateSql, [bookingId], (err) => {
    if (err) return res.status(500).send('Failed to confirm booking');

    res.redirect('/Member'); // or res.send('Booking payment confirmed!');
  });
});


app.get('/Booking/cancel-payment', (req, res) => {
  const { bookingId } = req.query;

  if (!bookingId) return res.status(400).send('Booking ID is required');

  const updateSql = `
    UPDATE Booking
    SET Status = 'Cancelled'
    WHERE BookingID = ? AND Status = 'Pending Payment'
  `;

  connection.query(updateSql, [bookingId], (err, result) => {
    if (err) return res.status(500).send('Failed to cancel booking');

    if (result.affectedRows === 0) {
      // No rows updated means booking either doesn't exist or is not pending payment
      return res.status(404).send('Booking not found or cannot be cancelled');
    }

    // Redirect back to Member page or confirmation page with flash message
    req.flash('success_msg', 'Booking payment cancelled successfully.');
    res.redirect('/Member');
  });
});




// Route to handle payment for a booking from the member home page
app.get('/Booking/pay', (req, res) => {
  const bookingId = req.query.bookingId;

  if (!bookingId) {
    return res.status(400).send('Booking ID is required');
  }

  const sql = `
    SELECT b.BookingID, b.BookingDate, b.StartTime, b.EndTime, b.AmountPaid, mt.TierName
    FROM Booking b
    JOIN members m ON b.fk_MemberID = m.MemberID
    JOIN membershiptier mt ON m.fk_TierID = mt.TierID
    WHERE b.BookingID = ? AND b.Status = 'Pending Payment'
  `;

  connection.query(sql, [bookingId], async (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).send('Server error');
    }

    if (results.length === 0) {
      return res.status(404).send('Booking not found or already paid');
    }

    const booking = results[0];
    const amountPaid = parseFloat(booking.AmountPaid);

    try {
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        line_items: [{
          price_data: {
            currency: 'usd',
            product_data: {
              name: `Booking #${booking.BookingID}`,
            },
            unit_amount: parseInt(amountPaid * 100), // in cents
          },
          quantity: 1,
        }],
        mode: 'payment',
        success_url: `http://localhost:3000/Booking/confirm-payment?bookingId=${booking.BookingID}`,
        cancel_url: `http://localhost:3000/Booking/cancel-payment?bookingId=${booking.BookingID}`,
      });

      //  Redirect to Stripe
      res.redirect(303, session.url);
    } catch (stripeError) {
      console.error('Stripe session error:', stripeError);
      res.status(500).send('Stripe session creation failed');
    }
  });
});

//stripe payment integration
// Route to create a Stripe Checkout session
app.post('/Booking/create-checkout-session', async (req, res) => {
  const { bookingId, amountPaid } = req.body;

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: {
            name: `Booking #${bookingId}`,
          },
          unit_amount: parseInt(parseFloat(amountPaid) * 100), // convert to cents
        },
        quantity: 1,
      }],
      mode: 'payment',
      success_url: `http://localhost:3000/Booking/confirm-payment?bookingId=${bookingId}`,
      cancel_url: `http://localhost:3000/Booking/cancel-payment?bookingId=${bookingId}`,
    });

    res.json({ id: session.id });
  } catch (err) {
    console.error('Stripe session error:', err);
    res.status(500).json({ error: 'Stripe session creation failed' });
  }
});


// Get all members with optional search
app.get('/admin/members', (req, res) => {
  const keyword = req.query.q || '';

  const memberQuery = `
    SELECT 
      m.*, 
      t.TierName, 
      MAX(c.Cashback_ExpiryDate) AS Cashback_ExpiryDate
    FROM members m
    LEFT JOIN membershiptier t ON m.Fk_TierID = t.TierID
    LEFT JOIN cashback c ON m.MemberID = c.fk_MemberID
    WHERE m.Member_FullName LIKE ? OR m.Member_Email LIKE ?
    GROUP BY m.MemberID
    ORDER BY m.Member_FullName
  `;

  const tierQuery = `SELECT * FROM membershiptier`;

  const admin = req.session.admin;

  connection.query(memberQuery, [`%${keyword}%`, `%${keyword}%`], (err, members) => {
    if (err) {
      console.error('Error loading members:', err);
      return res.status(500).send('Error loading members');
    }

    // Convert Cashback_ExpiryDate and ExpiryDate to Date objects for EJS formatting
    members.forEach(m => {
      if (m.Cashback_ExpiryDate) m.Cashback_ExpiryDate = new Date(m.Cashback_ExpiryDate);
      if (m.ExpiryDate) m.ExpiryDate = new Date(m.ExpiryDate);
    });

    connection.query(tierQuery, (err, tiers) => {
      if (err) {
        console.error('Error loading tiers:', err);
        return res.status(500).send('Error loading tiers');
      }

      res.render('Managemembersadmin', {
        members,
        tiers,
        keyword,
        editingMember: null,
        admin
      });
    });
  });
});

// Get form to edit a specific member by ID
app.get('/admin/members/edit/:id', (req, res) => {
  const memberId = req.params.id;
  const keyword = '';
  const admin = req.session.admin;

  const memberQuery = `SELECT * FROM members WHERE MemberID = ?`;
  const allMembersQuery = `
    SELECT m.*, t.TierName 
    FROM members m
    LEFT JOIN membershiptier t ON m.Fk_TierID = t.TierID
    ORDER BY m.Member_FullName
  `;
  const tierQuery = `SELECT * FROM membershiptier`;

  connection.query(memberQuery, [memberId], (err, result) => {
    if (err) {
      console.error('Error fetching member for edit:', err);
      return res.status(500).send('Failed to load member');
    }
    if (result.length === 0) return res.status(404).send('Member not found');

    const editingMember = result[0];

    connection.query(allMembersQuery, (err, members) => {
      if (err) {
        console.error('Error loading all members:', err);
        return res.status(500).send('Failed to load members');
      }

      connection.query(tierQuery, (err, tiers) => {
        if (err) {
          console.error('Error loading tiers:', err);
          return res.status(500).send('Failed to load tiers');
        }

        res.render('Managemembersadmin', {
          members,
          tiers,
          keyword,
          editingMember,
          admin
        });
      });
    });
  });
});

// Add or update member (handle form post)
app.post('/admin/members', (req, res) => {
  const { mode, memberId, fullName, email, password, phone, tierId, expiryDate } = req.body;
  const admin = req.session.admin;

  if (mode === 'edit') {
    // Editing existing member
    if (password && password.trim() !== '') {
      // Hash new password before update
      bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
          console.error('Password hashing error:', err);
          return res.status(500).render('Managemembersadmin', {
            error: 'Failed to hash password.',
            admin,
            members: [],
            tiers: [],
            keyword: '',
            editingMember: null
          });
        }

        const updateQuery = `
          UPDATE members 
          SET Member_FullName = ?, Member_Email = ?, Member_Password = ?, Member_Phone = ?, Fk_TierID = ?, ExpiryDate = ?
          WHERE MemberID = ?
        `;

        connection.query(updateQuery, [fullName, email, hashedPassword, phone, tierId, expiryDate, memberId], (err) => {
          if (err) {
            console.error('Update member error:', err);
            return res.status(500).render('Managemembersadmin', {
              error: 'Failed to update member.',
              admin,
              members: [],
              tiers: [],
              keyword: '',
              editingMember: null
            });
          }
          res.redirect('/admin/members');
        });
      });
    } else {
      // Update without changing password
      const updateQuery = `
        UPDATE members 
        SET Member_FullName = ?, Member_Email = ?, Member_Phone = ?, Fk_TierID = ?, ExpiryDate = ?
        WHERE MemberID = ?
      `;

      connection.query(updateQuery, [fullName, email, phone, tierId, expiryDate, memberId], (err) => {
        if (err) {
          console.error('Update member error:', err);
          return res.status(500).render('Managemembersadmin', {
            error: 'Failed to update member.',
            admin,
            members: [],
            tiers: [],
            keyword: '',
            editingMember: null
          });
        }
        res.redirect('/admin/members');
      });
    }
  } else {
    // Adding new member
    if (!password || password.trim() === '') {
      return res.status(400).render('Managemembersadmin', {
        error: 'Password is required.',
        admin,
        members: [],
        tiers: [],
        keyword: '',
        editingMember: null
      });
    }

    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        console.error('Password hashing error:', err);
        return res.status(500).render('Managemembersadmin', {
          error: 'Failed to hash password.',
          admin,
          members: [],
          tiers: [],
          keyword: '',
          editingMember: null
        });
      }

      const insertQuery = `
        INSERT INTO members 
          (Member_FullName, Member_Email, Member_Password, Member_Phone, Fk_TierID, JoinDate, ExpiryDate, CashbackBalance, Role)
        VALUES 
          (?, ?, ?, ?, ?, CURDATE(), ?, 0, 'Member')
      `;

      connection.query(insertQuery, [fullName, email, hashedPassword, phone, tierId, expiryDate], (err) => {
        if (err) {
          console.error('Add member error:', err);
          return res.status(500).render('Managemembersadmin', {
            error: 'Failed to add member.',
            admin,
            members: [],
            tiers: [],
            keyword: '',
            editingMember: null
          });
        }
        res.redirect('/admin/members');
      });
    });
  }
});

// Delete a member
// Delete a member with proper cascade deletion
app.post('/admin/member/delete/:id', (req, res) => {
  const memberId = req.params.id;

  // Start a transaction to ensure all deletions succeed or fail together
  connection.beginTransaction((err) => {
    if (err) {
      console.error('Transaction start error:', err);
      return res.status(500).send('Failed to start deletion process');
    }

    // Step 1: Delete from cashback table
    const deleteCashbackQuery = 'DELETE FROM cashback WHERE fk_MemberID = ?';
    connection.query(deleteCashbackQuery, [memberId], (err) => {
      if (err) {
        console.error('Error deleting cashback records:', err);
        return connection.rollback(() => {
          res.status(500).send('Failed to delete member cashback records');
        });
      }

      // Step 2: Delete from restaurantbill table
      const deleteRestaurantBillQuery = 'DELETE FROM restaurantbill WHERE fk_MemberID = ?';
      connection.query(deleteRestaurantBillQuery, [memberId], (err) => {
        if (err) {
          console.error('Error deleting restaurant bill records:', err);
          return connection.rollback(() => {
            res.status(500).send('Failed to delete member restaurant bills');
          });
        }

        // Step 3: Delete from allpurchases table
        const deletePurchaseQuery = 'DELETE FROM allpurchases WHERE fk_MemberID = ?';
        connection.query(deletePurchaseQuery, [memberId], (err) => {
          if (err) {
            console.error('Error deleting purchase records:', err);
            return connection.rollback(() => {
              res.status(500).send('Failed to delete member purchases');
            });
          }

          // Step 4: Delete from ticketpurchase table
          const deleteTicketPurchaseQuery = 'DELETE FROM ticketpurchase WHERE fk_MemberID = ?';
          connection.query(deleteTicketPurchaseQuery, [memberId], (err) => {
            if (err) {
              console.error('Error deleting ticket purchase records:', err);
              return connection.rollback(() => {
                res.status(500).send('Failed to delete member ticket purchases');
              });
            }

            // Step 5: Delete from booking table
            const deleteBookingQuery = 'DELETE FROM booking WHERE fk_MemberID = ?';
            connection.query(deleteBookingQuery, [memberId], (err) => {
              if (err) {
                console.error('Error deleting booking records:', err);
                return connection.rollback(() => {
                  res.status(500).send('Failed to delete member bookings');
                });
              }

              // Step 6: Finally delete the member
              const deleteMemberQuery = 'DELETE FROM members WHERE MemberID = ?';
              connection.query(deleteMemberQuery, [memberId], (err) => {
                if (err) {
                  console.error('Error deleting member:', err);
                  return connection.rollback(() => {
                    res.status(500).send('Failed to delete member');
                  });
                }

                // Commit the transaction
                connection.commit((err) => {
                  if (err) {
                    console.error('Transaction commit error:', err);
                    return connection.rollback(() => {
                      res.status(500).send('Failed to complete deletion');
                    });
                  }

                  console.log(` Member ${memberId} and all related records deleted successfully`);
                  res.redirect('/admin/members');
                });
              });
            });
          });
        });
      });
    });
  });
});

//cashback history viewing route
app.get('/admin/member/:memberId/cashback', (req, res) => {
  const memberId = req.params.memberId;
  const cashbackQuery = `
    SELECT Amount, EarnedFrom, EarnedDate, Cashback_ExpiryDate
    FROM cashback
    WHERE fk_MemberID = ?
    ORDER BY EarnedDate DESC
  `;
  connection.query(cashbackQuery, [memberId], (err, results) => {
    if (err) {
      console.error('Error fetching cashback data:', err);
      return res.status(500).json({ error: 'Failed to fetch cashback data' });
    }

    res.json(results);
  });
});




//cashback management
// Get all members with cashback info

// Show all bookings (list only)
app.get('/admin/bookings', (req, res) => {
  const query = `
    SELECT 
      b.BookingID,
      m.Member_FullName,
      m.Member_Email,
      t.TierName,
      b.BookingDate,
      b.StartTime,
      b.EndTime,
      b.Status,
      b.AmountPaid
    FROM Booking b
    JOIN members m ON b.Fk_MemberID = m.MemberID
    LEFT JOIN membershiptier t ON m.Fk_TierID = t.TierID
    ORDER BY b.BookingDate DESC
  `;

  connection.query(query, (err, results) => {
    if (err) return res.status(500).send('DB Error');

    res.render('managememberbookingadmin', {
      bookings: results,
      booking: null,   // no single booking, just list
      admin: req.session.admin
    });
  });
});

// Show edit form for a booking (also load full list to display below)
app.get('/admin/booking/edit/:id', (req, res) => {
  const bookingId = req.params.id;

  // Query single booking by ID
  const bookingQuery = `
    SELECT 
      b.BookingID,
      b.BookingDate,
      b.StartTime,
      b.EndTime,
      b.Status,
      b.AmountPaid,
      m.Member_FullName,
      m.Member_Email,
      t.TierName
    FROM Booking b
    JOIN members m ON b.Fk_MemberID = m.MemberID
    LEFT JOIN membershiptier t ON m.Fk_TierID = t.TierID
    WHERE b.BookingID = ?
  `;

  connection.query(bookingQuery, [bookingId], (err, bookingResults) => {
    if (err) return res.status(500).send('DB Error');
    if (bookingResults.length === 0) return res.status(404).send('Booking not found');

    // Also get all bookings for the list below the form
    const allBookingsQuery = `
      SELECT 
        b.BookingID,
        m.Member_FullName,
        m.Member_Email,
        t.TierName,
        b.BookingDate,
        b.StartTime,
        b.EndTime,
        b.Status,
        b.AmountPaid
      FROM Booking b
      JOIN members m ON b.Fk_MemberID = m.MemberID
      LEFT JOIN membershiptier t ON m.Fk_TierID = t.TierID
      ORDER BY b.BookingDate DESC
    `;

    connection.query(allBookingsQuery, (err2, allBookings) => {
      if (err2) return res.status(500).send('DB Error');

      res.render('managememberbookingadmin', {
        bookings: allBookings,
        booking: bookingResults[0],   // single booking to edit
        admin: req.session.admin
      });
    });
  });
});

// Handle edit form submission
app.post('/admin/booking/edit/:id', (req, res) => {
  const bookingId = req.params.id;
  const { BookingDate, StartTime, EndTime, Status, AmountPaid } = req.body;

  const updateQuery = `
    UPDATE Booking
    SET BookingDate = ?, StartTime = ?, EndTime = ?, Status = ?, AmountPaid = ?
    WHERE BookingID = ?
  `;

  connection.query(
    updateQuery,
    [BookingDate, StartTime, EndTime, Status, AmountPaid, bookingId],
    (err, results) => {
      if (err) return res.status(500).send('DB Error');
      res.redirect('/admin/bookings');
    }
  );
});

// Delete (cancel) a booking
app.post('/admin/booking/delete/:id', (req, res) => {
  const bookingId = req.params.id;

  const deleteQuery = 'DELETE FROM Booking WHERE BookingID = ?';

  connection.query(deleteQuery, [bookingId], (err, results) => {
    if (err) return res.status(500).send('DB Error');
    res.redirect('/admin/bookings');
  });
});

app.get('/About', (req, res) => {
  res.render('Aboutus'); // Assuming the file is views/Aboutus.ejs
});
// Sanjana


//-------------------------------------------------------------------------sanjana----------------------------------------------------





// Membership Tier & Incentive Management
//view current gold/silver/bronze tier rules(get)
//update tier benefits(put)




//  Single product page 
app.get('/product/:id', (req, res) => {
  const productId = req.params.id;
  const sql = 'SELECT * FROM storeitem WHERE ItemID = ?';

  connection.query(sql, [productId], (error, results) => {
    if (error) {
      console.error('Error fetching product:', error);
      return res.status(500).send('Error fetching product');
    }

    if (results.length === 0) {
      return res.status(404).send("Product not found");
    }

    res.render('productDetail', {
      product: results[0],
      member: req.session.member || {}
    });
  });
});



//kamali
// Member Routes
app.get('/membership', (req, res) => { //req-incoming req res-resp u get
  const member = req.session.member; //get data

  if (!member) {
    return res.redirect('/login'); // no member than redirect to login
  }

  // Get the membership tier name and expiry date from database
  const sql = `
    SELECT mt.TierName, m.ExpiryDate 
    FROM membershiptier mt 
    JOIN members m ON mt.TierID = m.fk_TierID 
    WHERE m.MemberID = ?
  `;

  connection.query(sql, [member.MemberID], (err, results) => {
    if (err) {
      console.error('Error fetching membership details:', err);
      return res.status(500).send('Internal Server Error');
    }

    if (results.length === 0) {
      return res.render('membership', { 
        currentTier: 'Unknown', 
        member,
        expiryDate: null 
      });
    }

    const currentTier = results[0].TierName;// its 0 cus query returns a array of rows but u only need one row per member
    const expiryDate = results[0].ExpiryDate;
    
    res.render('membership', { 
      currentTier, 
      member,
      expiryDate 
    });
  });
});

app.get('/managemembership', (req, res) => {
  const member = req.session.member;
  if (!member) return res.redirect('/login');

  const sql = 'SELECT TierName FROM membershiptier WHERE TierID = ?';

  connection.query(sql, [member.fk_TierID], (err, results) => {
    if (err) {
      console.error('Error fetching membership tier:', err);
      return res.status(500).send('Internal Server Error');
    }

    const currentTier = results.length > 0 ? results[0].TierName : 'Not Assigned';
    res.render('managemembership', { currentTier, member });
  });
});

// tier selection route with upgrade restrictions
app.post('/member/managemembership/select', (req, res) => {
  const { tier } = req.body;
  const member = req.session.member;
  
  if (!tier || !['Gold', 'Silver', 'Bronze'].includes(tier)) { //make sure no nulls are sent
    return res.status(400).json({ error: 'Invalid tier' });
  }

  if (!member) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  // Get current tier to check upgrade restrictions
  const sql = 'SELECT TierName FROM membershiptier WHERE TierID = ?';
  connection.query(sql, [member.fk_TierID], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }

    const currentTier = results.length > 0 ? results[0].TierName : 'Bronze';

    //  UPDATED: Upgrade restrictions
    if (currentTier === 'Gold') {
      return res.status(400).json({ 
        error: 'Gold members cannot downgrade. You already have the highest tier!' 
      });
    }

    if (currentTier === 'Silver' && tier === 'Bronze') {
      return res.status(400).json({ 
        error: 'Silver members cannot downgrade to Bronze. You can only upgrade to Gold!' 
      });
    }

    if (currentTier === tier) {
      return res.status(400).json({ 
        error: 'You are already on this tier!' 
      });
    }

    // Store selected tier in session temporarily
    req.session.selectedTier = tier;
    res.json({ success: true });
  });
});

//  UPDATED: Create checkout session with new pricing and upgrade logic
app.post('/member/managemembership/create-checkout-session', async (req, res) => {
  const member = req.session.member;
  const selectedTier = req.session.selectedTier;

  if (!member || !selectedTier) {
    return res.status(400).json({ error: 'No member or tier selected' });
  }

  // Get current tier
  const getCurrentTierSql = 'SELECT TierName FROM membershiptier WHERE TierID = ?';
  connection.query(getCurrentTierSql, [member.fk_TierID], async (tierErr, tierResults) => {
    if (tierErr) {
      return res.status(500).json({ error: 'Database error' });
    }

    const currentTier = tierResults.length > 0 ? tierResults[0].TierName : 'Bronze';//if query returns a result, extract the tier name. or else its bronze by default

    //  UPDATED: New pricing structure
    let price = 0;
    let description = '';

    if (selectedTier === 'Gold') {
      if (currentTier === 'Bronze') {
        price = 39.99; // Full price for Bronze to Gold
        description = 'Upgrade from Bronze to Gold - Full Access';
      } else if (currentTier === 'Silver') {
        price = 15.00; // Upgrade price for Silver to Gold
        description = 'Upgrade from Silver to Gold - Additional Features';
      }
    } else if (selectedTier === 'Silver') {
      if (currentTier === 'Bronze') {
        price = 24.99; // Full price for Bronze to Silver
        description = 'Upgrade from Bronze to Silver';
      }
    }

    // Validation
    if (currentTier === 'Gold') {
      return res.status(400).json({ error: 'Gold members cannot downgrade' });
    }

    if (currentTier === 'Silver' && selectedTier === 'Bronze') {
      return res.status(400).json({ error: 'Silver members cannot downgrade to Bronze' });
    }

    if (currentTier === selectedTier) {
      return res.status(400).json({ error: 'You are already on this tier' });
    }

    try {
      // Get tier ID from database
      const getTierSql = 'SELECT TierID FROM membershiptier WHERE TierName = ?';
      connection.query(getTierSql, [selectedTier], async (err, results) => {
        if (err || results.length === 0) {
          return res.status(500).json({ error: 'Failed to find tier details' });
        }

        const tierID = results[0].TierID;

        // Handle Bronze (this should not happen given restrictions, but keep for safety)
        if (selectedTier === 'Bronze') {
          return res.status(400).json({ error: 'Cannot downgrade to Bronze' });
        }

        //  UPDATED: Create one-time payment session with new pricing
        const session = await stripe.checkout.sessions.create({
          payment_method_types: ['card'],
          line_items: [{
            price_data: {
              currency: 'sgd',
              product_data: { 
                name: `${selectedTier} Membership Upgrade`,
                description: description
              },
              unit_amount: Math.round(price * 100), // Convert to cents
            },
            quantity: 1,
          }],
          mode: 'payment', // One-time payment
          success_url: 'http://localhost:3000/member/membership-success',
          cancel_url: 'http://localhost:3000/managemembership',
          metadata: {
            member_id: member.MemberID.toString(),
            tier_name: selectedTier,
            tier_id: tierID.toString(),
            current_tier: currentTier,
            upgrade_price: price.toString()
          }
        });

        // Store tier info in session for after payment
        req.session.pendingMembershipTier = {
          tierID: tierID,
          tierName: selectedTier,
          price: price,
          currentTier: currentTier
        };

        res.json({ url: session.url });
      });

    } catch (stripeError) {
      console.error('Stripe error:', stripeError);
      res.status(500).json({ error: 'Payment processing failed' });
    }
  });
});

//  UPDATED: Membership success page with expiry date handling
app.get('/member/membership-success', (req, res) => {
  const member = req.session.member;
  if (!member) return res.redirect('/login');

  // Check if there's a pending membership upgrade (from Stripe payment)
  const pendingTier = req.session.pendingMembershipTier;
  
  if (pendingTier) {
    console.log('Processing pending tier upgrade:', pendingTier);
    
    // Check if upgrading from Silver to Gold (preserve original expiry date)
    if (pendingTier.currentTier === 'Silver' && pendingTier.tierName === 'Gold') {
      console.log('Silver to Gold upgrade - preserving original expiry date');
      
      // Only update tier, keep existing expiry date
      const updateSql = 'UPDATE members SET fk_TierID = ? WHERE MemberID = ?';
      console.log('Executing SQL:', updateSql, 'with values:', [pendingTier.tierID, member.MemberID]);
      
      connection.query(updateSql, [pendingTier.tierID, member.MemberID], (updateErr, updateResult) => {
        if (updateErr) {
          console.error('Error updating membership after payment:', updateErr);
          return res.status(500).send('Failed to update membership');
        }
        
        console.log('Update result:', updateResult);
        
        // Update session with new tier
        req.session.member.fk_TierID = pendingTier.tierID;
        
        console.log(`Silver to Gold upgrade completed! Member ${member.MemberID} upgraded to ${pendingTier.tierName} for ${pendingTier.price} - Expiry date preserved`);
        
        // Clear pending data
        delete req.session.pendingMembershipTier;
        delete req.session.selectedTier;
        
        // Render success page with the NEW tier
        res.render('membershipsuccess', {
          member: req.session.member,
          newTier: pendingTier.tierName,
          previousTier: pendingTier.currentTier,
          upgradePaid: pendingTier.price,
          expiryDate: 'preserved' // Indicate expiry was preserved
        });
      });
      
    } else {
      // Bronze to Silver/Gold - set new expiry date (1 year from now)
      const expiryDate = new Date();
      expiryDate.setFullYear(expiryDate.getFullYear() + 1); // Add 1 year
      const formattedExpiryDate = expiryDate.toISOString().split('T')[0]; // Format as YYYY-MM-DD

      console.log('Setting new expiry date to:', formattedExpiryDate);
      
      
      // Update the member's tier AND expiry date for paid upgrades
      const updateSql = 'UPDATE members SET fk_TierID = ?, ExpiryDate = ? WHERE MemberID = ?';
      console.log('Executing SQL:', updateSql, 'with values:', [pendingTier.tierID, formattedExpiryDate, member.MemberID]);
      
      connection.query(updateSql, [pendingTier.tierID, formattedExpiryDate, member.MemberID], (updateErr, updateResult) => {
        if (updateErr) {
          console.error('Error updating membership after payment:', updateErr);
          return res.status(500).send('Failed to update membership');
        }
        
        console.log('Update result:', updateResult);
      if (updateErr) {
        console.error('Error updating membership after payment:', updateErr);
        return res.status(500).send('Failed to update membership');
      }

        // Update session with new tier
        req.session.member.fk_TierID = pendingTier.tierID;
        
        console.log(`Paid membership updated successfully! Member ${member.MemberID} upgraded from ${pendingTier.currentTier} to ${pendingTier.tierName} for ${pendingTier.price}. Expires on: ${formattedExpiryDate}`);
        
        // Clear pending data
        delete req.session.pendingMembershipTier;
        delete req.session.selectedTier;
        
        // Render success page with the NEW tier and expiry info
        res.render('membershipsuccess', {
          member: req.session.member,
          newTier: pendingTier.tierName,
          previousTier: pendingTier.currentTier,
          upgradePaid: pendingTier.price,
          expiryDate: formattedExpiryDate
        });
      });
    }
  } else {
    // No pending upgrade
    console.log('No pending tier found');
    
    // Get current tier from database
    const getTierSql = 'SELECT TierName FROM membershiptier WHERE TierID = ?';
    connection.query(getTierSql, [member.fk_TierID], (err, results) => {
      if (err || results.length === 0) {
        return res.render('membershipsuccess', {
          member: member,
          newTier: 'Unknown',
          previousTier: null,
          upgradePaid: 0,
          expiryDate: null
        });
      }

      const currentTier = results[0].TierName;//if u did an upgrade this will get your new tier name
      res.render('membershipsuccess', {
        member: member,
        newTier: currentTier,
        previousTier: null,
        upgradePaid: 0,
        expiryDate: null
      });
    });
  }
});

// NEW: Function to check and handle expired memberships
function checkExpiredMemberships() {
  const currentDate = new Date().toISOString().split('T')[0]; // Format: YYYY-MM-DD
  
  const expiredMembersSql = `
    UPDATE members 
    SET fk_TierID = 3 
    WHERE ExpiryDate < ? AND fk_TierID IN (1, 2) AND ExpiryDate IS NOT NULL
  `;
  
  connection.query(expiredMembersSql, [currentDate], (err, results) => {
    if (err) {
      console.error('Error checking expired memberships:', err);
      return;
    }
    
    if (results.affectedRows > 0) {
      console.log(`${results.affectedRows} expired memberships reverted to Bronze tier`);
    }
  });
}

// NEW: Run expiry check every hour (3600000 ms)
setInterval(checkExpiredMemberships, 3600000);

// NEW: Also run on server startup
checkExpiredMemberships();

// NEW: Middleware to check user's membership expiry on each request
app.use((req, res, next) => {
  if (req.session.member) {
    const currentDate = new Date().toISOString().split('T')[0];
    
    // Check if current user's membership has expired
    const checkUserExpirySql = `
      SELECT fk_TierID, ExpiryDate 
      FROM members 
      WHERE MemberID = ? AND ExpiryDate < ? AND fk_TierID IN (1, 2) AND ExpiryDate IS NOT NULL
    `;
    
    connection.query(checkUserExpirySql, [req.session.member.MemberID, currentDate], (err, results) => {
      if (err) {
        console.error('Error checking user expiry:', err);
        return next();
      }
      
      if (results.length > 0) {
        // User's membership has expired, revert to Bronze
        const revertSql = 'UPDATE members SET fk_TierID = 3 WHERE MemberID = ?';
        connection.query(revertSql, [req.session.member.MemberID], (revertErr) => {
          if (revertErr) {
            console.error('Error reverting expired membership:', revertErr);
          } else {
            // Update session
            req.session.member.fk_TierID = 3;
            console.log(`User ${req.session.member.MemberID} membership expired, reverted to Bronze`);
          }
          next();
        });
      } else {
        next();
      }
    });
  } else {
    next();
  }
});


// Route to show all events
app.get('/events', (req, res) => {
  const query = `
    SELECT * FROM event 
    WHERE EventDate > NOW() 
    AND (deleted IS NULL OR deleted = 0)
    ORDER BY EventDate ASC
  `;
  connection.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching events:', err);
      return res.status(500).send('Internal Server Error');
    }
    res.render('eventList', {
      events: results,
      member: req.session.member || {}
    });
  });
});

// FIXED: Route to show specific event details - with date validation AND deleted filter
app.get('/event/:id', (req, res) => {
  const eventId = req.params.id;
  const member = req.session.member;

  const eventQuery = `
    SELECT e.*, t.Published, t.TicketPrice,
           CASE WHEN e.EventDate > NOW() THEN 1 ELSE 0 END AS isUpcoming
    FROM event e
    LEFT JOIN ticket t ON e.EventID = t.Fk_EventID
    WHERE e.EventID = ? 
    AND (e.deleted IS NULL OR e.deleted = 0)
  `;

  const ticketCountQuery = 'SELECT COUNT(*) AS ticketsBought FROM ticketpurchase WHERE Fk_EventID = ?';

  connection.query(eventQuery, [eventId], (err, eventResult) => {
    if (err || eventResult.length === 0) {
      console.error('Error fetching event:', err);
      return res.status(404).send('Event not found or no longer available');
    }

    const event = eventResult[0];

    if (event.isUpcoming === 0) {
      return res.render('eventDetail', {
        event,
        member,
        ticketsLeft: 0,
        ticketPublished: false,
        eventEnded: true
      });
    }

    connection.query(ticketCountQuery, [eventId], (err, ticketResult) => {
      if (err) {
        console.error('Error counting tickets:', err);
        return res.status(500).send('Error fetching ticket data');
      }

      const ticketsBought = ticketResult[0].ticketsBought || 0;
      const ticketsLeft = event.Capacity != null ? event.Capacity - ticketsBought : 'Unlimited';

      res.render('eventDetail', {
        event,
        member,
        ticketsLeft,
        ticketPublished: event.Published || false,
        eventEnded: false
      });
    });
  });
});


app.get('/Admin/events', (req, res) => {
  const admin = req.session.admin;
  if (!admin) return res.redirect('/login'); // Or handle unauthorized

  res.render('admincreateevent', { admin });
});

function showFields(type) {
  document.querySelectorAll('.dynamic-section').forEach(el => el.style.display = 'none');
  if (type === 'Club Match') {
    document.getElementById('matchFields').style.display = 'block';
  } else if (type === 'Training Session') {
    document.getElementById('trainingFields').style.display = 'block';
  } else if (type === 'AGM') {
    document.getElementById('agmFields').style.display = 'block';
  } else if (type === 'Trial') {
    document.getElementById('trialFields').style.display = 'block';
  } else if (type === 'Regular Event') {
  }
}



// UPDATED: Create event route with start and end times for all events
app.post('/Admin/events/create', upload.single('eventpic'), (req, res) => {
  const {
    title,
    eventType,
    eventDate,
    startTime,        // NEW: Start time for all events
    endTime,          // NEW: End time for all events
    location,
    description,
    coach,
    meetingRoom,
    eventSession,
    capacity
  } = req.body;

  const toNull = (val) => {
    if (typeof val === 'string') {
      return val.trim() !== '' ? val.trim() : null;
    }
    return val !== undefined && val !== '' ? val : null;
  };

  // NEW: Helper function to handle time values
  const toTimeNull = (val) => {
    if (typeof val === 'string' && val.trim() !== '') {
      // Convert time string (HH:MM) to TIME format for database
      // MySQL TIME format expects HH:MM:SS, so we append :00 for seconds
      return val.trim() + ':00';
    }
    return null;
  };

  const eventpic = req.file ? req.file.filename : null;
  const fk_AdminID = req.session.admin?.AdminID;

  if (!fk_AdminID) return res.status(401).send('Unauthorized');

  // UPDATED: SQL to include Start_Time and End_Time instead of trial-specific times
  const sql = `
    INSERT INTO event 
    (fk_AdminID, Title, EventType, EventDate, Start_Time, End_Time, Location, Description, Eventpic, Coach, Meeting_Room, EventSession, Capacity)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  // UPDATED: Values array with start and end times for all events
  const values = [
    fk_AdminID,
    title,
    eventType,
    eventDate,
    toTimeNull(startTime),  
    toTimeNull(endTime),      
    location,
    description,
    eventpic,
    toNull(coach),
    toNull(meetingRoom),
    toNull(eventSession),
    eventType === 'AGM' ? null : toNull(capacity) 
  ];
  console.log('VALUES:', values);
  connection.query(sql, values, (err) => {
    if (err) {
      console.error('Insert error:', err.sqlMessage || err.message);
      return res.status(500).send('Error creating event');
    }
    res.redirect('/Admin');
  });
});





// Routes for Admin Store

// GET all products - Updated to handle showAll and message parameters
app.get('/admin/store-items', (req, res) => {
    if (!req.session.admin) return res.redirect('/login');
    
    const showAll = req.query.showAll === 'true';
    const showForceDelete = req.query.showForceDelete; // Get the item ID for force delete
    let sql = 'SELECT * FROM storeitem';
    
    if (!showAll) {
        sql += ' WHERE is_active = TRUE';
    }
    
    connection.query(sql, (error, results) => {
        if (error) {
            console.error("Error fetching store items:", error);
            return res.status(500).send('Error fetching store items');
        }
        
        res.render('adminstore', {
            items: results,
            admin: req.session.admin,
            showAll: showAll,
            message: req.query.message,
            showForceDelete: showForceDelete // Pass the force delete item ID
        });
    });
});

//memberstore get routes
app.get('/store-items', (req, res) => {
    const category = req.query.category;
    const message = req.query.message; // Get message from URL
    
    let sql = 'SELECT * FROM storeitem WHERE is_active = TRUE';
    let params = [];
    
    if (category) {
        sql += ' AND Category = ?';
        params.push(category);
    }
    
    connection.query(sql, params, (error, results) => {
        if (error) {
            console.error('Error fetching store items:', error);
            return res.status(500).send('Error fetching store items');
        }

        console.log('Message being passed to template:', message); // Debug log

        res.render('memberstore', {
            items: results,
            member: req.session.member || {},
            selectedCategory: category || 'All',
            message: message  // Pass message to template
        });
    });
});

// Single product page 
app.get('/product/:id', (req, res) => {
  const productId = req.params.id;
  const sql = 'SELECT * FROM storeitem WHERE ItemID = ?';

  connection.query(sql, [productId], (error, results) => {
    if (error) {
      console.error('Error fetching product:', error);
      return res.status(500).send('Error fetching product');
    }

    if (results.length === 0) {
      return res.status(404).send("Product not found");
    }

    res.render('productDetail', {
      product: results[0],
      member: req.session.member || {}
    });
  });
});

//route to add products
// GET route: show the Add Item form
app.get('/admin/addItem', (req, res) => {
  if (!req.session.admin) return res.redirect('/login');
  res.render('addItem', {
    admin: req.session.admin
  });
});

// POST route: handle form submission with image upload using multer
app.post('/admin/addItem', upload.single('Image'), (req, res) => {
  if (!req.session.admin) return res.redirect('/login');
  const { Name, Category, Price, itemquantity } = req.body;
  const storeitempic = req.file ? req.file.filename : null;
  const sql = 'INSERT INTO storeitem (Name, Category, Price, itemquantity, storeitempic) VALUES (?, ?, ?, ?, ?)';
  connection.query(sql, [Name, Category, Price, itemquantity, storeitempic], (error, results) => {
    if (error) {
      console.error("Error adding store item:", error);
      return res.status(500).send('Error adding store item');
    }
    
    const successMessage = encodeURIComponent('Store item added successfully');
    res.redirect(`/admin/store-items?message=${successMessage}`);
  });
});

// Update product page
app.get('/admin/editItem/:id', (req, res) => {
  const itemId = req.params.id;
  const sql = 'SELECT * FROM storeitem WHERE ItemID = ?';
  connection.query(sql, [itemId], (error, results) => {
    if (error) {
      console.error('Database query error:', error.message);
      return res.status(500).send('Error retrieving item by ID');
    }
    if (results.length > 0) {
      res.render('editItem', { item: results[0], admin: req.session.admin }); // Include admin object
    } else {
      res.status(404).send('Store item not found');
    }
  });
});

// Update product 
app.post('/admin/editItem/:id', upload.single('Image'), (req, res) => {
  const itemId = req.params.id;
  const { Name, Category, Price, itemquantity } = req.body;
  
  // Enhanced debugging
  console.log('=== EDIT ITEM DEBUG ===');
  console.log('Request body:', req.body);
  console.log('Item ID:', itemId);
  console.log('Category received:', Category);
  console.log('Category type:', typeof Category);
  console.log('Category length:', Category ? Category.length : 'undefined');
  
  // Validate required fields
  if (!Name || !Category || !Price || itemquantity === undefined) {
    console.error('Missing required fields:', {
      Name: !!Name,
      Category: !!Category,
      Price: !!Price,
      itemquantity: itemquantity !== undefined
    });
    return res.status(400).send('Missing required fields');
  }
  
  const Image = req.file ? req.file.filename : null;
  let sql, params;
  
  if (Image) {
    sql = 'UPDATE storeitem SET Name = ?, Category = ?, Price = ?, itemquantity = ?, storeitempic = ? WHERE ItemID = ?';
    params = [Name, Category, Price, itemquantity, Image, itemId];
  } else {
    sql = 'UPDATE storeitem SET Name = ?, Category = ?, Price = ?, itemquantity = ? WHERE ItemID = ?';
    params = [Name, Category, Price, itemquantity, itemId];
  }
  
  console.log('SQL:', sql);
  console.log('Params:', params);
  
  connection.query(sql, params, (error, results) => {
    if (error) {
      console.error('Database error:', error);
      return res.status(500).send('Error updating store item: ' + error.message);
    }
    

    console.log('Update results:', results);
    console.log('Affected rows:', results.affectedRows);
    console.log('Changed rows:', results.changedRows);
    
    // Verify the update by querying the item
    const verifySql = 'SELECT * FROM storeitem WHERE ItemID = ?';
    connection.query(verifySql, [itemId], (verifyError, verifyResults) => {
      if (verifyError) {
        console.error('Verification error:', verifyError);
      } else {
        console.log('Updated item:', verifyResults[0]);
      }
      
      const successMessage = encodeURIComponent('Store item updated successfully');
      res.redirect(`/admin/store-items?message=${successMessage}`);
    });
  });
});

// List item (make active/visible)
app.get('/listItem/:id', (req, res) => {
    if (!req.session.admin) return res.redirect('/login');
    
    const itemId = req.params.id;
    const sql = 'UPDATE storeitem SET is_active = TRUE WHERE ItemID = ?';
    
    connection.query(sql, [itemId], (error, results) => {
        if (error) {
            console.error("Error listing item:", error);
            return res.status(500).send('Error listing item');
        }
        
        const successMessage = encodeURIComponent('Item successfully listed in store');
        res.redirect(`/admin/store-items?message=${successMessage}`);
    });
});

// Unlist item (make inactive/hidden but keep in database)
app.get('/unlistItem/:id', (req, res) => {
    if (!req.session.admin) return res.redirect('/login');
    
    const itemId = req.params.id;
    
    // Mark item as unlisted instead of deleting
    const sql = 'UPDATE storeitem SET is_active = FALSE WHERE ItemID = ?';
    
    connection.query(sql, [itemId], (error, results) => {
        if (error) {
            console.error("Error unlisting item:", error);
            return res.status(500).send('Error unlisting item');
        }
        
        const successMessage = encodeURIComponent('Item unlisted from store (purchase history preserved)');
        res.redirect(`/admin/store-items?message=${successMessage}`);
    });
});

// DELETE store item completely from database (ENHANCED VERSION)
app.post('/admin/deleteItem/:id', (req, res) => {
  if (!req.session.admin) return res.redirect('/login');
  
  const itemId = req.params.id;
  const forceDelete = req.body.forceDelete === 'true'; // Check if force delete was requested
  
  console.log(`Admin attempting to delete store item ${itemId}, forceDelete: ${forceDelete}`);
  
  if (forceDelete) {
    // FORCE DELETE: Remove item regardless of purchase history
    console.log(`🔥 FORCE DELETE requested for item ${itemId}`);
    
    // Start transaction to ensure data consistency
    connection.beginTransaction((err) => {
      if (err) {
        console.error('Transaction start error:', err);
        const errorMessage = encodeURIComponent('Failed to start deletion process');
        return res.redirect(`/admin/store-items?message=${errorMessage}`);
      }

      // Step 1: Delete all purchase records for this item
      const deletePurchasesSql = 'DELETE FROM purchasestoreitem WHERE fk_ItemID = ?';
      
      connection.query(deletePurchasesSql, [itemId], (purchaseErr, purchaseResult) => {
        if (purchaseErr) {
          return connection.rollback(() => {
            console.error('Error deleting purchase records:', purchaseErr);
            const errorMessage = encodeURIComponent('Failed to delete purchase records');
            res.redirect(`/admin/store-items?message=${errorMessage}`);
          });
        }

        console.log(`🗑️ Deleted ${purchaseResult.affectedRows} purchase records for item ${itemId}`);

        // Step 2: Delete the item itself
        const deleteItemSql = 'DELETE FROM storeitem WHERE ItemID = ?';
        
        connection.query(deleteItemSql, [itemId], (itemErr, itemResult) => {
          if (itemErr) {
            return connection.rollback(() => {
              console.error('Error deleting store item:', itemErr);
              const errorMessage = encodeURIComponent('Failed to delete store item');
              res.redirect(`/admin/store-items?message=${errorMessage}`);
            });
          }

          if (itemResult.affectedRows === 0) {
            return connection.rollback(() => {
              const notFoundMessage = encodeURIComponent('Store item not found');
              res.redirect(`/admin/store-items?message=${notFoundMessage}`);
            });
          }

          // Commit the transaction
          connection.commit((commitErr) => {
            if (commitErr) {
              return connection.rollback(() => {
                console.error('Transaction commit error:', commitErr);
                const errorMessage = encodeURIComponent('Failed to complete deletion');
                res.redirect(`/admin/store-items?message=${errorMessage}`);
              });
            }

            console.log(` FORCE DELETE completed for item ${itemId} and all purchase records`);
            const successMessage = encodeURIComponent('Item and ALL purchase history permanently deleted');
            res.redirect(`/admin/store-items?message=${successMessage}`);
          });
        });
      });
    });

  } else {
    // NORMAL DELETE: Check purchase history first
    const checkPurchasesSql = 'SELECT COUNT(*) as purchaseCount FROM purchasestoreitem WHERE fk_ItemID = ?';
    
    connection.query(checkPurchasesSql, [itemId], (checkErr, checkResults) => {
      if (checkErr) {
        console.error('Error checking for existing purchases:', checkErr);
        const errorMessage = encodeURIComponent('Error checking purchase history');
        return res.redirect(`/admin/store-items?message=${errorMessage}`);
      }

      const purchaseCount = checkResults[0].purchaseCount;

      if (purchaseCount > 0) {
        // Item has been purchased - redirect with warning and force delete option
        console.log(` Item ${itemId} has ${purchaseCount} purchases, offering force delete`);
        const warningMessage = encodeURIComponent(`Cannot delete: ${purchaseCount} purchase record(s) exist. Use 'Unlist' to hide, or 'Force Delete' to permanently remove everything.`);
        res.redirect(`/admin/store-items?message=${warningMessage}&showForceDelete=${itemId}`);
        
      } else {
        // Item has never been purchased - safe to delete normally
        console.log(` Item ${itemId} has no purchases, safe to delete`);
        
        const deleteSql = 'DELETE FROM storeitem WHERE ItemID = ?';
        
        connection.query(deleteSql, [itemId], (deleteErr, deleteResult) => {
          if (deleteErr) {
            console.error('Error deleting store item:', deleteErr);
            const errorMessage = encodeURIComponent('Failed to delete store item');
            return res.redirect(`/admin/store-items?message=${errorMessage}`);
          }
          
          if (deleteResult.affectedRows === 0) {
            const notFoundMessage = encodeURIComponent('Store item not found');
            return res.redirect(`/admin/store-items?message=${notFoundMessage}`);
          }
          
          console.log(` Store item ${itemId} deleted (no purchase history)`);
          const successMessage = encodeURIComponent('Store item permanently deleted successfully');
          res.redirect(`/admin/store-items?message=${successMessage}`);
        });
      }
    });
  }
});

// ROUTE FOR ADDING TO CART
// Adding items to cart - FIXED: Now uses quantity from form
app.post('/store/add-to-cart/:id', (req, res) => {
  const itemId = req.params.id;
  const quantity = parseInt(req.body.quantity) || 1; // Get quantity from form
  const memberId = req.session.member?.MemberID;

  const sql = 'SELECT * FROM storeitem WHERE ItemID = ?';
  connection.query(sql, [itemId], (error, results) => {
    if (error) {
      console.error('Error finding item:', error);
      return res.status(500).send('Error adding to cart');
    }

    if (results.length === 0) {
      return res.status(404).send('Item not found');
    }

    const item = results[0];

    if (!req.session.cart) {
      req.session.cart = [];
    }

    // FIXED: Now properly uses the quantity from the form
    const existing = req.session.cart.find(i => i.id === item.ItemID && i.type !== 'ticket');
    if (existing) {
      existing.quantity += quantity; //  Use quantity from form
    } else {
      req.session.cart.push({
        id: item.ItemID,
        type: 'item', 
        name: item.Name,
        price: item.Price,
        storeitempic: item.storeitempic,
        quantity: quantity //  Use quantity from form instead of hardcoded 1
      });
    }

    //  FIXED: Redirect back to store with success message (same as restaurant)
    const itemName = item.Name || 'Item';
    const successMessage = `${itemName} (x${quantity}) added to cart successfully!`;
    res.redirect(`/store-items?message=${encodeURIComponent(successMessage)}`);
  });
});

// Route to add ticket to cart - with date validation
app.post('/add-ticket-to-cart/:eventId', (req, res) => {
  if (!req.session.member) return res.redirect('/login');
  
  const eventId = req.params.eventId;
  
  // Get event and ticket details WITH DATE CHECK
  const eventTicketSql = `
    SELECT 
      e.EventID,
      e.Title,
      e.EventDate,
      e.Location,
      e.Capacity,
      t.TicketPrice,
      t.Published
    FROM event e
    JOIN ticket t ON e.EventID = t.Fk_EventID
    WHERE e.EventID = ? 
      AND t.Published = TRUE
      AND e.EventDate > NOW()
  `;
  
  connection.query(eventTicketSql, [eventId], (err, results) => {
    if (err) {
      console.error('Error fetching event ticket:', err);
      return res.status(500).send('Error adding ticket to cart');
    }
    
    if (results.length === 0) {
      return res.status(404).send('Ticket not available, not published, or event has already occurred');
    }
    
    const eventTicket = results[0];
    
    // Check if event is sold out
    const ticketCountSql = 'SELECT COUNT(*) AS ticketsSold FROM ticketpurchase WHERE Fk_EventID = ?';
    connection.query(ticketCountSql, [eventId], (countErr, countResults) => {
      if (countErr) {
        console.error('Error checking ticket availability:', countErr);
        return res.status(500).send('Error checking ticket availability');
      }
      
      const ticketsSold = countResults[0].ticketsSold || 0;
      const ticketsLeft = eventTicket.Capacity ? eventTicket.Capacity - ticketsSold : 999;
      
      if (ticketsLeft <= 0) {
        return res.status(400).send('Event is sold out');
      }
      
      // Initialize cart if it doesn't exist
      if (!req.session.cart) {
        req.session.cart = [];
      }
      
      // Check if this ticket is already in cart
      const existingTicket = req.session.cart.find(item => 
        item.type === 'ticket' && item.id === parseInt(eventId)
      );
      
      if (existingTicket) {
        // Check if adding one more would exceed capacity
        if (eventTicket.Capacity && (ticketsSold + existingTicket.quantity + 1) > eventTicket.Capacity) {
          return res.status(400).send('Not enough tickets available');
        }
        existingTicket.quantity += 1;
      } else {
        // Add new ticket to cart
        req.session.cart.push({
          id: parseInt(eventId),
          type: 'ticket',
          name: `${eventTicket.Title} - Ticket`,
          price: parseFloat(eventTicket.TicketPrice),
          eventDate: eventTicket.EventDate,
          location: eventTicket.Location,
          quantity: 1,
          maxQuantity: Math.min(ticketsLeft, 5)
        });
      }
      
      console.log('Ticket added to cart:', eventTicket.Title);
      res.redirect('/cart');
    });
  });
});
// Updated remove from cart to handle both types
app.post('/store/remove-from-cart/:type/:id', (req, res) => {
  if (!req.session.cart) return res.redirect('/cart');
  
  const itemType = req.params.type; // 'item' or 'ticket'
  const itemId = parseInt(req.params.id);
  
  req.session.cart = req.session.cart.filter(item => {
    if (itemType === 'ticket') {
      return !(item.type === 'ticket' && item.id === itemId);
    } else {
      return !(item.type !== 'ticket' && item.id === itemId);
    }
  });
  
  res.redirect('/cart');
});

// Backward compatibility: old remove route for existing templates
app.post('/store/remove-from-cart/:id', (req, res) => {
  if (!req.session.cart) return res.redirect('/cart');
  const itemId = parseInt(req.params.id);
  req.session.cart = req.session.cart.filter(item => 
    !(item.type !== 'ticket' && item.id === itemId)
  );
  res.redirect('/cart');
});

// Updated quantity update to handle both types
app.post('/store/update-cart-all', (req, res) => {
  const quantitiesArray = req.body.quantities;

  console.log('Received quantities:', quantitiesArray);

  if (req.session.cart && Array.isArray(quantitiesArray)) {
    req.session.cart = req.session.cart.map((item, index) => {
      const qtyStr = quantitiesArray[index];
      const newQty = parseInt(qtyStr, 10);
      console.log(`Updating item ${item.id} with qtyStr: ${qtyStr}`);
      console.log(`Parsed quantity: ${newQty}`);

      if (!isNaN(newQty) && newQty > 0) {
        // For tickets, check max quantity limit
        if (item.type === 'ticket' && item.maxQuantity) {
          item.quantity = Math.min(newQty, item.maxQuantity);
        } else {
          item.quantity = newQty;
        }
      }
      return item;
    });
  }

  res.redirect('/cart');
});

// Enhanced cart route with cashback selection and ticket support - UPDATED with restaurant support
app.get('/cart', (req, res) => {
  if (!req.session.member) return res.redirect('/login');

  const cart = req.session.cart || [];
  const memberID = req.session.member.MemberID;

  if (cart.length === 0) {
    return res.render('cart', { 
      cart, 
      member: req.session.member, 
      pricing: {},
      cashbackRecords: [],
      totalAvailableCashback: 0,
      totalAmount: 0,
      discountAmount: 0,
      subtotalAfterDiscount: 0,
      storeItemsTotal: 0,
      restaurantItemsTotal: 0,
      ticketsTotal: 0
    });
  }

  // Get available cashback records for selection
  const availableCashbackSql = `
    SELECT 
      CashbackID,
      Amount,
      EarnedFrom,
      EarnedDate,
      Cashback_ExpiryDate,
      UserTransactionno,
      DATEDIFF(Cashback_ExpiryDate, CURDATE()) as DaysLeft
    FROM cashback
    WHERE fk_MemberID = ? 
      AND Cashback_ExpiryDate > CURDATE()
      AND Amount > 0
    ORDER BY Cashback_ExpiryDate ASC, EarnedDate ASC
  `;

  connection.query(availableCashbackSql, [memberID], (err, cashbackRecords) => {
    if (err) {
      console.error('Error fetching cashback records:', err);
      cashbackRecords = [];
    }

    // Calculate total available cashback
    const totalAvailableCashback = cashbackRecords.reduce((sum, record) => 
      sum + parseFloat(record.Amount), 0
    );

    // Get member's tier info for discount calculation
    const memberSql = `
      SELECT m.fk_TierID, t.Cashback, t.Discount, m.CashbackBalance, t.TierName
      FROM members m
      JOIN membershiptier t ON m.fk_TierID = t.TierID
      WHERE m.MemberID = ?
    `;

    connection.query(memberSql, [memberID], (tierErr, tierResults) => {
      if (tierErr) {
        console.error('Error fetching tier info:', tierErr);
        return res.status(500).send('Error loading tier info');
      }

      const { Cashback: cashbackRate, Discount: discountRate, CashbackBalance, TierName } = tierResults[0] || {};
      
      // Calculate totals for store items, restaurant items, and tickets
      const totalAmount = cart.reduce((sum, item) => sum + item.price * item.quantity, 0);
      
      // Separate totals for display purposes - UPDATED to exclude restaurant items from store total
      const storeItemsTotal = cart
        .filter(item => item.type !== 'ticket' && item.type !== 'restaurant')
        .reduce((sum, item) => sum + item.price * item.quantity, 0);
      
      // NEW: Restaurant items total
      const restaurantItemsTotal = cart
        .filter(item => item.type === 'restaurant')
        .reduce((sum, item) => sum + item.price * item.quantity, 0);
      
      const ticketsTotal = cart
        .filter(item => item.type === 'ticket')
        .reduce((sum, item) => sum + item.price * item.quantity, 0);
      
      // Apply discount to TOTAL amount (store items + restaurant items + tickets)
      const discountAmount = totalAmount * (discountRate || 0);
      const subtotalAfterDiscount = totalAmount - discountAmount;

      // Calculate pricing for display (compatible with your existing template)
      const pricing = {
        totalAmount,
        storeItemsTotal,
        restaurantItemsTotal,
        ticketsTotal,
        discountAmount,
        subtotalAfterDiscount,
        cashbackUsed: 0, // Will be calculated dynamically on frontend
        finalAmount: subtotalAfterDiscount
      };

      // Add pricing data to member object
      const memberWithPricing = {
        ...req.session.member,
        discountRate: discountRate || 0,
        cashbackRate: cashbackRate || 0,
        cashbackBalance: CashbackBalance || 0,
        tierName: TierName || 'No Tier'
      };

      res.render('cart', {
        cart,
        member: memberWithPricing,
        pricing,
        cashbackRecords: cashbackRecords || [],
        totalAvailableCashback: Math.round(totalAvailableCashback * 100) / 100,
        // Add these for backward compatibility with your current template
        totalAmount,
        discountAmount,
        subtotalAfterDiscount,
        discountRate: discountRate || 0,
        cashbackRate: cashbackRate || 0,
        CashbackBalance: CashbackBalance || 0,
        storeItemsTotal,
        restaurantItemsTotal,
        ticketsTotal
      });
    });
  });
});

// Enhanced checkout route with selected cashback handling and ticket support - UPDATED for restaurant items
app.post('/store/checkout', async (req, res) => {
  if (!req.session.member) return res.redirect('/login');
  const cart = req.session.cart || [];
  if (cart.length === 0) return res.status(400).json({ error: 'Cart is empty' });

  const memberID = req.session.member.MemberID;
  const selectedCashback = req.body.selectedCashback || [];

  console.log('=== SELECTED CASHBACK CHECKOUT ===');
  console.log('Selected cashback items:', selectedCashback);

  const memberSql = `
    SELECT m.fk_TierID, t.Cashback, t.Discount
    FROM members m
    JOIN membershiptier t ON m.fk_TierID = t.TierID
    WHERE m.MemberID = ?
  `;

  connection.query(memberSql, [memberID], async (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Error fetching tier' });
    }
    if (results.length === 0) {
      return res.status(500).json({ error: 'Membership tier not found' });
    }

    const { Cashback: cashbackRate, Discount: discountRate } = results[0];
    const totalAmount = cart.reduce((sum, item) => sum + item.price * item.quantity, 0);
    
    // Apply discount to TOTAL amount (store items + restaurant items + tickets)
    const discountAmount = Math.round(totalAmount * discountRate * 100) / 100;
    const subtotalAfterDiscount = Math.round((totalAmount - discountAmount) * 100) / 100;

    // Process selected cashback
    if (selectedCashback.length > 0) {
      const cashbackIds = selectedCashback.map(item => item.id);
      const validateCashbackSql = `
        SELECT CashbackID, Amount, Cashback_ExpiryDate
        FROM cashback
        WHERE CashbackID IN (${cashbackIds.map(() => '?').join(',')})
          AND fk_MemberID = ?
          AND Cashback_ExpiryDate > NOW()
          AND Amount > 0
      `;

      connection.query(validateCashbackSql, [...cashbackIds, memberID], async (cashbackErr, cashbackResults) => {
        if (cashbackErr) {
          console.error('Error validating cashback:', cashbackErr);
          return res.status(500).json({ error: 'Error validating cashback' });
        }

        // Calculate total cashback to use
        let totalCashbackUsed = 0;
        const validCashbackItems = [];

        for (const selected of selectedCashback) {
          const cashbackRecord = cashbackResults.find(r => r.CashbackID == selected.id);
          if (cashbackRecord) {
            const amountToUse = Math.min(
              parseFloat(selected.amount),
              parseFloat(cashbackRecord.Amount),
              subtotalAfterDiscount - totalCashbackUsed
            );

            if (amountToUse > 0) {
              totalCashbackUsed += amountToUse;
              validCashbackItems.push({
                id: cashbackRecord.CashbackID,
                originalAmount: parseFloat(cashbackRecord.Amount),
                amountUsed: amountToUse
              });
            }
          }
        }

        totalCashbackUsed = Math.min(totalCashbackUsed, subtotalAfterDiscount);

        console.log('=== CASHBACK CALCULATION ===');
        console.log('Subtotal after discount:', subtotalAfterDiscount);
        console.log('Valid cashback items:', validCashbackItems);
        console.log('Total cashback used:', totalCashbackUsed);

        const finalAmount = Math.round((subtotalAfterDiscount - totalCashbackUsed) * 100) / 100;
        const cashbackEarned = Math.round(finalAmount * cashbackRate * 100) / 100;

        console.log('Final amount:', finalAmount);
        console.log('Cashback earned:', cashbackEarned);

        // Create payment intent
        try {
          const paymentIntent = await stripeStore.paymentIntents.create({
            amount: Math.round(finalAmount * 100),
            currency: 'usd',
          });

          console.log('PaymentIntent created successfully:', paymentIntent.id);

          req.session.pendingOrder = {
            cart,
            totalAmount,
            discountAmount,
            cashbackUsed: totalCashbackUsed,
            cashbackEarned,
            finalAmount,
            paymentIntentId: paymentIntent.id,
            selectedCashbackItems: validCashbackItems
          };

          res.json({
            clientSecret: paymentIntent.client_secret,
            amount: finalAmount,
            paymentIntentId: paymentIntent.id,
            cashbackUsed: totalCashbackUsed,
            cashbackEarned
          });
        } catch (stripeError) {
          console.error('Stripe error:', stripeError);
          res.status(500).json({
            error: 'Payment processing error: ' + stripeError.message
          });
        }
      });
    } else {
      // No cashback selected - proceed normally
      const finalAmount = subtotalAfterDiscount;
      const cashbackEarned = Math.round(finalAmount * cashbackRate * 100) / 100;

      try {
        const paymentIntent = await stripeStore.paymentIntents.create({
          amount: Math.round(finalAmount * 100),
          currency: 'usd',
        });

        req.session.pendingOrder = {
          cart,
          totalAmount,
          discountAmount,
          cashbackUsed: 0,
          cashbackEarned,
          finalAmount,
          paymentIntentId: paymentIntent.id,
          selectedCashbackItems: []
        };

        res.json({
          clientSecret: paymentIntent.client_secret,
          amount: finalAmount,
          paymentIntentId: paymentIntent.id,
          cashbackUsed: 0,
          cashbackEarned
        });
      } catch (stripeError) {
        console.error('Stripe error:', stripeError);
        res.status(500).json({
          error: 'Payment processing error: ' + stripeError.message
        });
      }
    }
  });
});

// UPDATED: Checkout confirm route - Now includes restaurant item support
app.post('/store/checkout/confirm', async (req, res) => {
  console.log(' CHECKOUT CONFIRM ROUTE CALLED!');
  console.log('=== CONFIRM UNIFIED CHECKOUT WITH RESTAURANT SUPPORT ===');

  if (!req.session.member || !req.session.pendingOrder) {
    return res.status(400).json({ error: 'No pending order' });
  }

  const {
    cart,
    totalAmount,
    discountAmount,
    cashbackUsed,
    cashbackEarned,
    finalAmount,
    paymentIntentId,
    selectedCashbackItems
  } = req.session.pendingOrder;

  console.log('Processing unified order with cart:', cart);

  // Verify payment intent
  try {
    const paymentIntent = await stripeStore.paymentIntents.retrieve(paymentIntentId);
    if (paymentIntent.status !== 'succeeded') {
      return res.status(400).json({ error: 'Payment not completed' });
    }
  } catch (stripeError) {
    console.error('Error verifying PaymentIntent:', stripeError);
    return res.status(500).json({ error: 'Payment verification failed' });
  }

  const memberID = req.session.member.MemberID;
  const storeItems = cart.filter(item => item.type === 'item' || (!item.type && item.storeitempic));
  const restaurantItems = cart.filter(item => item.type === 'restaurant');
  const tickets = cart.filter(item => item.type === 'ticket');

  console.log('Items breakdown:');
  console.log('- Store items:', storeItems.length);
  console.log('- Restaurant items:', restaurantItems.length);
  console.log('- Tickets:', tickets.length);

  const orderTimestamp = new Date();
  
  //  UPDATED: Create main purchase record with DiscountAmount and CashbackEarned
  const purchaseSql = `
    INSERT INTO allpurchases
    (fk_MemberID, PurchaseDate, TotalAmount, DiscountAmount, CashbackUsed, FinalAmountPaid)
    VALUES (?, ?, ?, ?, ?, ?)
  `;

  connection.query(purchaseSql, [memberID, orderTimestamp, totalAmount, discountAmount, cashbackUsed, finalAmount], (err, result) => {
    if (err) {
      console.error('Error saving main purchase:', err);
      return res.status(500).json({ error: 'Error saving purchase' });
    }

    const purchaseID = result.insertId;
    console.log('Main purchase saved with ID:', purchaseID);

    let operationsCompleted = 0;
    const totalOperations = (storeItems.length > 0 ? 1 : 0) + 
                           (restaurantItems.length > 0 ? 1 : 0) + 
                           (tickets.length > 0 ? 1 : 0);

    if (totalOperations === 0) {
      return processCashbackAndComplete(selectedCashbackItems, purchaseID, memberID, cashbackEarned, req, res);
    }

    // STEP 2: Process store items
    if (storeItems.length > 0) {
      processStoreItems(storeItems, purchaseID, () => {
        operationsCompleted++;
        if (operationsCompleted === totalOperations) {
          processCashbackAndComplete(selectedCashbackItems, purchaseID, memberID, cashbackEarned, req, res);
        }
      });
    }

    // STEP 3: Process restaurant items
    if (restaurantItems.length > 0) {
      processRestaurantItems(restaurantItems, purchaseID, memberID, orderTimestamp, () => {
        operationsCompleted++;
        if (operationsCompleted === totalOperations) {
          processCashbackAndComplete(selectedCashbackItems, purchaseID, memberID, cashbackEarned, req, res);
        }
      });
    }

    // STEP 4: Process tickets
    if (tickets.length > 0) {
      processTickets(tickets, purchaseID, memberID, orderTimestamp, () => {
        operationsCompleted++;
        if (operationsCompleted === totalOperations) {
          processCashbackAndComplete(selectedCashbackItems, purchaseID, memberID, cashbackEarned, req, res);
        }
      });
    }
  });
});

// Helper function to process store items
function processStoreItems(storeItems, purchaseID, callback) {
  let itemsProcessed = 0;
  
  storeItems.forEach(item => {
    const itemTotalAmount = item.price * item.quantity;
    
    const itemSql = `
      INSERT INTO purchasestoreitem
      (fk_PurchaseTransactionID, fk_ItemID, Quantity, TotalAmount)
      VALUES (?, ?, ?, ?)
    `;

    connection.query(itemSql, [
      purchaseID,
      item.id,
      item.quantity,
      itemTotalAmount
    ], (itemErr) => {
      if (itemErr) {
        console.error('Error saving store item:', itemErr);
      } else {
        console.log(`Store item saved: ${item.name} x${item.quantity} = $${itemTotalAmount}`);
        
        // Reduce stock
        const updateStockSql = `
          UPDATE storeitem 
          SET itemquantity = itemquantity - ? 
          WHERE ItemID = ?
        `;
        
        connection.query(updateStockSql, [item.quantity, item.id], (stockErr) => {
          if (stockErr) {
            console.error('Error updating store stock:', stockErr);
          } else {
            console.log(` Store stock reduced for item ${item.id}: -${item.quantity}`);
          }
        });
      }

      itemsProcessed++;
      if (itemsProcessed === storeItems.length) {
        callback();
      }
    });
  });
}

//  UPDATED: Restaurant items processing - using only TotalAmount, removed FinalAmountPaid and CashbackUsed
function processRestaurantItems(restaurantItems, purchaseID, memberID, orderTimestamp, callback) {
  let itemsProcessed = 0;
  const totalRestaurantItems = restaurantItems.reduce((sum, item) => sum + item.quantity, 0);
  
  console.log(`Processing ${totalRestaurantItems} restaurant items...`);
  
  restaurantItems.forEach(item => {
    // Insert each restaurant item quantity into restaurantbill table
    for (let i = 0; i < item.quantity; i++) {
      const restaurantBillSql = `
        INSERT INTO restaurantbill 
        (fk_MemberID, fk_ItemID, BillDate, TotalAmount, fk_PurchaseTransactionID)
        VALUES (?, ?, ?, ?, ?)
      `;
      
      connection.query(restaurantBillSql, [
        memberID,
        item.id,
        orderTimestamp,
        item.price,  //  Individual item price stored in TotalAmount
        purchaseID
      ], (restaurantErr, restaurantResult) => {
        if (restaurantErr) {
          console.error('Error saving restaurant item:', restaurantErr);
        } else {
          console.log(`Restaurant item saved: ${item.name} with bill ID ${restaurantResult.insertId}, price: $${item.price}`);
        }
        
        itemsProcessed++;
        if (itemsProcessed === totalRestaurantItems) {
          console.log(`All ${totalRestaurantItems} restaurant items processed successfully`);
          callback();
        }
      });
    }
  });
}

// Helper function to process tickets
function processTickets(tickets, purchaseID, memberID, orderTimestamp, callback) {
  let ticketsProcessed = 0;
  const totalTicketCount = tickets.reduce((sum, ticket) => sum + ticket.quantity, 0);
  
  console.log(`Processing ${totalTicketCount} tickets...`);
  
  tickets.forEach(ticket => {
    for (let i = 0; i < ticket.quantity; i++) {
      const ticketPurchaseSql = `
        INSERT INTO ticketpurchase 
        (fk_MemberID, Fk_EventID, PurchaseDate, TotalAmount, fk_PurchaseTransactionID)
        VALUES (?, ?, ?, ?, ?)
      `;
      
      connection.query(ticketPurchaseSql, [
        memberID,
        ticket.id,
        orderTimestamp,
        ticket.price,  //  Now using TotalAmount instead of FinalAmountPaid
        purchaseID
      ], (ticketErr, ticketResult) => {
        if (ticketErr) {
          console.error('Error saving ticket purchase:', ticketErr);
        } else {
          console.log(`Ticket saved for event ${ticket.id} with ID ${ticketResult.insertId}, price: $${ticket.price}`);
        }
        
        ticketsProcessed++;
        if (ticketsProcessed === totalTicketCount) {
          console.log(`All ${totalTicketCount} tickets processed successfully`);
          callback();
        }
      });
    }
  });
}

// Helper function to process cashback and complete order
function processCashbackAndComplete(selectedCashbackItems, purchaseID, memberID, cashbackEarned, req, res) {
  if (selectedCashbackItems.length > 0) {
    processIndividualCashbackUsage(selectedCashbackItems, purchaseID, memberID, cashbackEarned, () => {
      completeOrder(req, res, purchaseID, cashbackEarned);
    });
  } else {
    // Just record cashback earning if there was any
    if (cashbackEarned > 0) {
      recordCashbackEarning(memberID, cashbackEarned, purchaseID, () => {
        completeOrder(req, res, purchaseID, cashbackEarned);
      });
    } else {
      completeOrder(req, res, purchaseID, cashbackEarned);
    }
  }
}

// Helper function to process individual cashback usage
function processIndividualCashbackUsage(selectedCashbackItems, purchaseID, memberID, cashbackEarned, callback) {
  console.log('=== PROCESSING INDIVIDUAL CASHBACK USAGE ===');
  
  let cashbackOperations = 0;
  const totalOperations = selectedCashbackItems.length + (cashbackEarned > 0 ? 1 : 0);
  
  // Process each selected cashback item
  selectedCashbackItems.forEach(item => {
    // Record usage
    const insertUsageSql = `
      INSERT INTO cashback 
      (fk_MemberID, Amount, EarnedFrom, EarnedDate, Cashback_ExpiryDate, fk_PurchaseTransactionID, UserTransactionno)
      VALUES (?, ?, 'Store Purchase - Used', NOW(), DATE_ADD(NOW(), INTERVAL 1 YEAR), ?, ?)
    `;
    
    const usageTransactionNo = `TXN-USAGE-${Date.now()}-${item.id}`;
    
    connection.query(insertUsageSql, [
      memberID,
      -item.amountUsed,
      purchaseID,
      usageTransactionNo
    ], (usageErr) => {
      if (usageErr) {
        console.error('Error recording cashback usage:', usageErr);
      } else {
        console.log(` Cashback usage recorded: -$${item.amountUsed.toFixed(2)} from cashback ${item.id}`);
      }
      
      // Update the original cashback record if partially used
      if (item.amountUsed < item.originalAmount) {
        const updateOriginalSql = `
          UPDATE cashback 
          SET Amount = Amount - ? 
          WHERE CashbackID = ? AND fk_MemberID = ?
        `;
        
        connection.query(updateOriginalSql, [item.amountUsed, item.id, memberID], (updateErr) => {
          if (updateErr) {
            console.error('Error updating original cashback record:', updateErr);
          } else {
            console.log(` Original cashback ${item.id} updated: remaining $${(item.originalAmount - item.amountUsed).toFixed(2)}`);
          }
          
          cashbackOperations++;
          if (cashbackOperations === totalOperations) {
            callback();
          }
        });
      } else {
        // Fully used - mark as depleted
        const deleteSql = `
          UPDATE cashback 
          SET Amount = 0 
          WHERE CashbackID = ? AND fk_MemberID = ?
        `;
        
        connection.query(deleteSql, [item.id, memberID], (deleteErr) => {
          if (deleteErr) {
            console.error('Error marking cashback as used:', deleteErr);
          } else {
            console.log(` Cashback ${item.id} fully used`);
          }
          
          cashbackOperations++;
          if (cashbackOperations === totalOperations) {
            callback();
          }
        });
      }
    });
  });
  
  // Record cashback earning
  if (cashbackEarned > 0) {
    recordCashbackEarning(memberID, cashbackEarned, purchaseID, () => {
      cashbackOperations++;
      if (cashbackOperations === totalOperations) {
        callback();
      }
    });
  }
}

// Helper function to record cashback earning
function recordCashbackEarning(memberID, cashbackEarned, purchaseID, callback) {
  if (cashbackEarned <= 0) {
    callback();
    return;
  }
  
  const insertEarningSql = `
    INSERT INTO cashback 
    (fk_MemberID, Amount, EarnedFrom, EarnedDate, Cashback_ExpiryDate, fk_PurchaseTransactionID, UserTransactionno)
    VALUES (?, ?, 'Store Purchase - Earned', NOW(), DATE_ADD(NOW(), INTERVAL 1 YEAR), ?, ?)
  `;
  
  const earningTransactionNo = `TXN-EARN-${Date.now()}-${memberID}`;
  
  connection.query(insertEarningSql, [
    memberID,
    cashbackEarned,
    purchaseID,
    earningTransactionNo
  ], (earningErr) => {
    if (earningErr) {
      console.error('Error recording cashback earning:', earningErr);
    } else {
      console.log(` Cashback earning recorded: +${cashbackEarned.toFixed(2)}`);
    }
    callback();
  });
}

// Helper function to complete the order
function completeOrder(req, res, purchaseID, cashbackEarned) {
  // Update member's balance from cashback table
  const memberID = req.session.member.MemberID;
  const updateBalanceSql = `
    UPDATE members 
    SET CashbackBalance = (
      SELECT COALESCE(SUM(Amount), 0)
      FROM cashback 
      WHERE fk_MemberID = ? AND Cashback_ExpiryDate > NOW() AND Amount > 0
    )
    WHERE MemberID = ?
  `;
  
  connection.query(updateBalanceSql, [memberID, memberID], (balanceErr) => {
    if (balanceErr) {
      console.error('Error updating member balance:', balanceErr);
    } else {
      console.log(' Member balance updated from cashback records');
    }
    
    // Clear session
    req.session.cart = [];
    req.session.pendingOrder = null;
    
    console.log('Order processing complete');
    res.json({
      success: true,
      message: 'Order saved successfully!',
      purchaseID,
      cashbackEarned
    });
  });
}

// REPLACE your existing /store/past-orders route with this updated version
app.get('/store/past-orders', (req, res) => {
  const email = req.session.member?.Member_Email;
  if (!email) return res.redirect('/login');

  connection.query('SELECT * FROM members WHERE Member_Email = ?', [email], (err, results) => {
    if (err || results.length === 0) {
      console.error('Error fetching member details:', err);
      return res.status(500).send('User not found');
    }

    const member = results[0];
    const memberId = member.MemberID;

    console.log('Fetching unified past orders for MemberID:', memberId);

    //  UPDATED: Get all purchase records with DiscountAmount
    const mainOrdersSql = `
      SELECT 
        PurchaseTransactionID,
        PurchaseDate,
        TotalAmount,
        DiscountAmount,
        CashbackUsed,
        FinalAmountPaid
      FROM allpurchases
      WHERE fk_MemberID = ?
      ORDER BY PurchaseDate DESC
    `;

    connection.query(mainOrdersSql, [memberId], (orderErr, orderResults) => {
      if (orderErr) {
        console.error('Error fetching orders:', orderErr);
        return res.status(500).send('Failed to load orders');
      }

      console.log('Main orders found:', orderResults.length);

      //  UPDATED: Get standalone ticket purchases using TotalAmount
      const standaloneTicketsSql = `
        SELECT 
          tp.TicketPurchaseID,
          tp.PurchaseDate,
          tp.TotalAmount,
          COUNT(*) as ticket_count,
          'ticket_only' as OrderType
        FROM ticketpurchase tp
        WHERE tp.fk_MemberID = ? 
          AND tp.fk_PurchaseTransactionID IS NULL
        GROUP BY DATE(tp.PurchaseDate), HOUR(tp.PurchaseDate), MINUTE(tp.PurchaseDate)
        ORDER BY tp.PurchaseDate DESC
      `;

      connection.query(standaloneTicketsSql, [memberId], (ticketErr, standaloneTickets) => {
        if (ticketErr) {
          console.error('Error fetching standalone tickets:', ticketErr);
          standaloneTickets = [];
        }

        console.log('Standalone ticket groups found:', standaloneTickets.length);

        //  UPDATED: Combine orders using TotalAmount
        const allOrderGroups = [
          ...orderResults.map(order => ({ ...order, OrderType: 'main' })),
          ...standaloneTickets.map(ticket => ({
            PurchaseTransactionID: null,
            PurchaseDate: ticket.PurchaseDate,
            TotalAmount: ticket.TotalAmount * ticket.ticket_count,
            DiscountAmount: 0,
            CashbackUsed: 0,
            FinalAmountPaid: ticket.TotalAmount * ticket.ticket_count,
            OrderType: 'ticket_only'
          }))
        ];

        if (allOrderGroups.length === 0) {
          console.log('No orders found for member ID:', memberId);
          return res.render('past-orders', { member, orders: [] });
        }

        // Sort all orders by date
        allOrderGroups.sort((a, b) => new Date(b.PurchaseDate) - new Date(a.PurchaseDate));

        // Process each order to get store items, restaurant items, and tickets
        let processedOrders = 0;
        const detailedOrders = [];

        allOrderGroups.forEach(order => {
          const orderDetails = {
            ...order,
            orderId: order.PurchaseTransactionID || `TICKET-${new Date(order.PurchaseDate).getTime()}`,
            storeItems: [],
            restaurantItems: [],
            tickets: []
          };

          let subOperations = 0;
          const totalSubOperations = 3; // Store items + Restaurant items + Tickets

          if (order.OrderType === 'main') {
            //  UPDATED: Get store items using TotalAmount
            const storeItemsSql = `
              SELECT 
                pi.fk_ItemID, 
                pi.Quantity, 
                pi.TotalAmount,
                COALESCE(i.Name, 'Removed Item') as Name, 
                COALESCE(i.Price, 0) as Price, 
                COALESCE(i.Category, 'N/A') as Category,
                i.storeitempic,
                COALESCE(i.is_active, FALSE) as is_active
              FROM purchasestoreitem pi
              LEFT JOIN storeitem i ON pi.fk_ItemID = i.ItemID
              WHERE pi.fk_PurchaseTransactionID = ?
            `;

            connection.query(storeItemsSql, [order.PurchaseTransactionID], (itemErr, itemResults) => {
              if (itemErr) {
                console.error('Error fetching store items for order', order.PurchaseTransactionID, ':', itemErr);
                orderDetails.storeItems = [];
              } else {
                orderDetails.storeItems = itemResults || [];
                console.log(`Found ${(itemResults || []).length} store items for order ${order.PurchaseTransactionID}`);
              }

              subOperations++;
              checkComplete();
            });

            //  UPDATED: Get restaurant items using TotalAmount
            const restaurantItemsSql = `
              SELECT 
                rb.fk_ItemID,
                rb.TotalAmount,
                rb.BillDate,
                COALESCE(ri.Name, 'Removed Food Item') as Name,
                COALESCE(ri.Description, '') as Description,
                COALESCE(ri.Price, 0) as Price,
                ri.Image,
                COUNT(*) as quantity
              FROM restaurantbill rb
              LEFT JOIN restaurantitem ri ON rb.fk_ItemID = ri.ItemID
              WHERE rb.fk_PurchaseTransactionID = ?
              GROUP BY rb.fk_ItemID, ri.Name, ri.Description, ri.Price, ri.Image
            `;

            connection.query(restaurantItemsSql, [order.PurchaseTransactionID], (restaurantErr, restaurantResults) => {
              if (restaurantErr) {
                console.error('Error fetching restaurant items for order', order.PurchaseTransactionID, ':', restaurantErr);
                orderDetails.restaurantItems = [];
              } else {
                orderDetails.restaurantItems = restaurantResults || [];
                console.log(`Found ${(restaurantResults || []).length} restaurant items for order ${order.PurchaseTransactionID}`);
                
                if (restaurantResults && restaurantResults.length > 0) {
                  console.log('Restaurant items data:', restaurantResults);
                }
              }

              subOperations++;
              checkComplete();
            });

            //  UPDATED: Get tickets using TotalAmount instead of FinalAmountPaid
            const ticketsSql = `
              SELECT 
                tp.TicketPurchaseID, 
                tp.Fk_EventID, 
                tp.PurchaseDate, 
                tp.TotalAmount,
                COALESCE(e.EventID, tp.Fk_EventID) as EventID,
                COALESCE(e.Title, 'Unknown Event') as Title,
                e.EventDate,
                COALESCE(e.Location, 'Location TBD') as Location,
                COALESCE(e.EventType, 'Event') as EventType,
                COALESCE(t.TicketPrice, tp.TotalAmount, 0) as TicketPrice
              FROM ticketpurchase tp
              LEFT JOIN event e ON tp.Fk_EventID = e.EventID
              LEFT JOIN ticket t ON e.EventID = t.Fk_EventID
              WHERE tp.fk_PurchaseTransactionID = ?
            `;

            connection.query(ticketsSql, [order.PurchaseTransactionID], (ticketErr, ticketResults) => {
              if (ticketErr) {
                console.error('Error fetching tickets for order', order.PurchaseTransactionID, ':', ticketErr);
                orderDetails.tickets = [];
              } else {
                orderDetails.tickets = ticketResults || [];
                console.log(`Found ${(ticketResults || []).length} tickets for order ${order.PurchaseTransactionID}`);
              }

              subOperations++;
              checkComplete();
            });

          } else {
            // For standalone ticket orders, no store items or restaurant items
            orderDetails.storeItems = [];
            orderDetails.restaurantItems = [];
            
            //  UPDATED: Get tickets for standalone orders using TotalAmount
            const standaloneTicketDetailsSql = `
              SELECT 
                tp.TicketPurchaseID, 
                tp.Fk_EventID, 
                tp.PurchaseDate, 
                tp.TotalAmount,
                COALESCE(e.EventID, tp.Fk_EventID) as EventID,
                COALESCE(e.Title, 'Unknown Event') as Title,
                e.EventDate,
                COALESCE(e.Location, 'Location TBD') as Location,
                COALESCE(e.EventType, 'Event') as EventType
              FROM ticketpurchase tp
              LEFT JOIN event e ON tp.Fk_EventID = e.EventID
              WHERE tp.fk_MemberID = ? 
                AND tp.fk_PurchaseTransactionID IS NULL
                AND tp.PurchaseDate = ?
            `;

            connection.query(standaloneTicketDetailsSql, [memberId, order.PurchaseDate], (ticketErr, ticketResults) => {
              if (ticketErr) {
                console.error('Error fetching standalone tickets:', ticketErr);
                orderDetails.tickets = [];
              } else {
                orderDetails.tickets = ticketResults || [];
                console.log(`Found ${(ticketResults || []).length} standalone tickets for date ${order.PurchaseDate}`);
              }

              detailedOrders.push(orderDetails);
              processedOrders++;
              if (processedOrders === allOrderGroups.length) {
                renderUnifiedOrdersPage();
              }
            });
          }

          function checkComplete() {
            if (subOperations === totalSubOperations) {
              detailedOrders.push(orderDetails);
              processedOrders++;
              if (processedOrders === allOrderGroups.length) {
                renderUnifiedOrdersPage();
              }
            }
          }
        });

        function renderUnifiedOrdersPage() {
          //  UPDATED: Sort by order number (newest first) instead of date
          detailedOrders.sort((a, b) => {
            // Extract numeric order ID for proper sorting
            const getOrderNumber = (order) => {
              if (order.PurchaseTransactionID) {
                return order.PurchaseTransactionID; // Main orders use PurchaseTransactionID
              } else {
                return order.standaloneTicketId || 0; // Standalone tickets use TicketPurchaseID
              }
            };
            
            const orderNumA = getOrderNumber(a);
            const orderNumB = getOrderNumber(b);
            
            return orderNumB - orderNumA; // Descending order (newest first)
          });
          
          console.log('Rendering unified orders page with', detailedOrders.length, 'orders (sorted by order number)');
          
          // DEBUG: Log order numbers for verification
          detailedOrders.forEach((order, index) => {
            console.log(`Order ${index + 1}: ID=${order.orderId}, PurchaseID=${order.PurchaseTransactionID}, TicketID=${order.standaloneTicketId}`);
          });
          
          // Add order type classification
          detailedOrders.forEach(order => {
            const hasStoreItems = order.storeItems && order.storeItems.length > 0;
            const hasRestaurantItems = order.restaurantItems && order.restaurantItems.length > 0;
            const hasTickets = order.tickets && order.tickets.length > 0;
            
            const itemCount = (hasStoreItems ? 1 : 0) + (hasRestaurantItems ? 1 : 0) + (hasTickets ? 1 : 0);
            
            if (itemCount > 1) {
              order.orderType = 'mixed';
              order.orderTypeLabel = 'Mixed Order';
            } else if (hasStoreItems) {
              order.orderType = 'store';
              order.orderTypeLabel = 'Store Order';
            } else if (hasRestaurantItems) {
              order.orderType = 'restaurant';
              order.orderTypeLabel = 'Restaurant Order';
            } else if (hasTickets) {
              order.orderType = 'ticket';
              order.orderTypeLabel = 'Ticket Order';
            } else {
              order.orderType = 'empty';
              order.orderTypeLabel = 'Empty Order';
            }
          });
          
          res.render('past-orders', {
            member,
            orders: detailedOrders
          });
        }
      }); 
    });
  }); 
}); 


app.get('/Admin/addadmins', (req, res) => {
  if (!req.session.admin) return res.redirect('/login');
  
  // Fetch all admins from database
  connection.query('SELECT * FROM clubadmin ORDER BY Admin_FullName', (err, admins) => {
    if (err) {
      console.error('Error fetching admins:', err);
      return res.status(500).send('Failed to load admins');
    }
    
    res.render('addadmins', {  // Render addadmins.ejs (not manageadmins)
      admin: req.session.admin, 
      admins: admins,
      message: req.query.message || null
    });
  });
});

// POST - Add new admin
app.post('/Admin/addadmins', async (req, res) => {
  const { fullName, email, phone, password, role } = req.body;
  if (!req.session.admin) return res.redirect('/login');

  try {
    // Check if email already exists
    connection.query('SELECT * FROM clubadmin WHERE Admin_Email = ?', [email], async (err, existingAdmins) => {
      if (err) {
        console.error('Error checking existing admin:', err);
        return res.redirect('/Admin/addadmins?message=Error checking existing admin');
      }

      if (existingAdmins.length > 0) {
        return res.redirect('/Admin/addadmins?message=Admin with this email already exists');
      }

      // Hash password and create admin
      const hashedPassword = await bcrypt.hash(password, 10);

      connection.query(
        `INSERT INTO clubadmin (Admin_FullName, Admin_Email, Admin_Phone, Admin_Password, Role) VALUES (?, ?, ?, ?, ?)`,
        [fullName, email, phone, hashedPassword, role || 'Admin'],
        (err, result) => {
          if (err) {
            console.error('Error creating admin:', err);
            return res.redirect('/Admin/addadmins?message=Failed to add admin');
          }
          res.redirect('/Admin/addadmins?message=Admin added successfully');
        }
      );
    });
  } catch (err) {
    console.error('Hashing error:', err);
    res.redirect('/Admin/addadmins?message=Internal server error');
  }
});

// POST - Edit admin details
app.post('/Admin/editadmin/:id', (req, res) => {
  const adminId = req.params.id;
  const { fullName, email, phone, role } = req.body;
  
  if (!req.session.admin) return res.redirect('/login');

  // Check if email already exists for other admins
  connection.query(
    'SELECT * FROM clubadmin WHERE Admin_Email = ? AND AdminID != ?', 
    [email, adminId], 
    (err, existingAdmins) => {
      if (err) {
        console.error('Error checking existing admin:', err);
        return res.redirect('/Admin/addadmins?message=Error checking existing admin');
      }

      if (existingAdmins.length > 0) {
        return res.redirect('/Admin/addadmins?message=Another admin with this email already exists');
      }

      // Update admin details
      connection.query(
        `UPDATE clubadmin SET Admin_FullName = ?, Admin_Email = ?, Admin_Phone = ?, Role = ? WHERE AdminID = ?`,
        [fullName, email, phone, role, adminId],
        (err, result) => {
          if (err) {
            console.error('Error updating admin:', err);
            return res.redirect('/Admin/addadmins?message=Failed to update admin');
          }
          
          if (result.affectedRows === 0) {
            return res.redirect('/Admin/addadmins?message=Admin not found');
          }
          
          // If current user updated their own info, update session
          if (parseInt(adminId) === req.session.admin.AdminID) {
            req.session.admin.Admin_FullName = fullName;
            req.session.admin.Admin_Email = email;
            req.session.admin.Admin_Phone = phone;
            req.session.admin.Role = role;
          }
          
          res.redirect('/Admin/addadmins?message=Admin updated successfully');
        }
      );
    }
  );
});

// POST - Change admin password
app.post('/Admin/changepassword/:id', async (req, res) => {
  const adminId = req.params.id;
  const { newPassword } = req.body;
  
  if (!req.session.admin) return res.redirect('/login');

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    connection.query(
      'UPDATE clubadmin SET Admin_Password = ? WHERE AdminID = ?',
      [hashedPassword, adminId],
      (err, result) => {
        if (err) {
          console.error('Error changing password:', err);
          return res.redirect('/Admin/addadmins?message=Failed to change password');
        }
        
        if (result.affectedRows === 0) {
          return res.redirect('/Admin/addadmins?message=Admin not found');
        }
        
        const message = parseInt(adminId) === req.session.admin.AdminID 
          ? 'Your password has been changed successfully' 
          : 'Admin password changed successfully';
        
        res.redirect(`/Admin/addadmins?message=${encodeURIComponent(message)}`);
      }
    );
  } catch (err) {
    console.error('Password hashing error:', err);
    res.redirect('/Admin/addadmins?message=Internal server error');
  }
});

// POST - Delete admin
app.post('/Admin/deleteadmin/:id', (req, res) => {
  const adminId = req.params.id;
  
  if (!req.session.admin) return res.redirect('/login');
  
  // Prevent admin from deleting themselves
  if (parseInt(adminId) === req.session.admin.AdminID) {
    return res.redirect('/Admin/addadmins?message=Cannot delete your own account');
  }

  // Check if this is the last admin (optional safety check)
  connection.query('SELECT COUNT(*) as count FROM clubadmin', (err, countResult) => {
    if (err) {
      console.error('Error counting admins:', err);
      return res.redirect('/Admin/addadmins?message=Error checking admin count');
    }

    if (countResult[0].count <= 1) {
      return res.redirect('/Admin/addadmins?message=Cannot delete the last admin account');
    }

    // Delete the admin
    connection.query(
      'DELETE FROM clubadmin WHERE AdminID = ?',
      [adminId],
      (err, result) => {
        if (err) {
          console.error('Error deleting admin:', err);
          return res.redirect('/Admin/addadmins?message=Failed to delete admin');
        }
        
        if (result.affectedRows === 0) {
          return res.redirect('/Admin/addadmins?message=Admin not found');
        }
        
        res.redirect('/Admin/addadmins?message=Admin deleted successfully');
      }
    );
  });
});






// Display event management page - UPDATED for new time fields
app.get('/Admin/eventmanagementadmin', (req, res) => {
  // Only show non-deleted events in event management
  const query = 'SELECT * FROM event WHERE deleted IS NULL OR deleted = FALSE';
  connection.query(query, (err, events) => {
    if (err) {
      console.error('Error retrieving events:', err);
      return res.status(500).send('Internal server error');
    }

    // Convert relevant fields - UPDATED to handle new Start_Time and End_Time fields
    events = events.map(event => {
      return {
        ...event,
        EventDate: event.EventDate ? new Date(event.EventDate) : null,
        // For TIME fields, keep them as strings (MySQL returns them as strings)
        Start_Time: event.Start_Time || null,
        End_Time: event.End_Time || null,
      };
    });

    res.render('eventmanagementadmin', { 
      events,
      admin: req.session.admin || {}
    });
  });
});

// Update event inline - UPDATED to handle Start_Time and End_Time for all events
app.post('/Admin/events/update/:id', (req, res) => {
  const eventId = req.params.id;
  const {
    Title,
    EventType,
    EventDate,
    Start_Time,
    End_Time,
    Location,
    Description,
    Coach,
    Meeting_Room,
    EventSession,
    Capacity
  } = req.body;

  // Helper function to handle null/empty values
  const toNull = (val) => {
    if (typeof val === 'string') {
      return val.trim() !== '' ? val.trim() : null;
    }
    return val !== undefined && val !== '' ? val : null;
  };

  // Helper function to handle time values
  const toTimeNull = (val) => {
    if (typeof val === 'string' && val.trim() !== '') {
      // Convert time string (HH:MM) to TIME format for database
      // MySQL TIME format expects HH:MM:SS, so we append :00 for seconds
      return val.trim() + ':00';
    }
    return null;
  };

  // UPDATED SQL to use Start_Time and End_Time
  const query = `
    UPDATE event SET
      Title = ?, EventType = ?, EventDate = ?, Start_Time = ?, End_Time = ?, Location = ?, Description = ?,
      Coach = ?, Meeting_Room = ?, EventSession = ?, Capacity = ?
    WHERE EventID = ?
  `;

  const values = [
    Title, 
    EventType, 
    EventDate, 
    toTimeNull(Start_Time),    // All events now have start time
    toTimeNull(End_Time),      // All events now have end time
    Location, 
    Description,
    toNull(Coach), 
    toNull(Meeting_Room), 
    toNull(EventSession), 
    EventType === 'AGM' ? null : toNull(Capacity), 
    eventId
  ];

  console.log('Update VALUES:', values);

  connection.query(query, values, (err, result) => {
    if (err) {
      console.error('Error updating event:', err.sqlMessage || err.message);
      return res.status(500).send('Error updating event');
    }
    
    if (result.affectedRows === 0) {
      return res.status(404).send('Event not found');
    }
    
    res.redirect('/Admin/eventmanagementadmin');
  });
});

// Delete event route - UPDATED to preserve tickets and ticket purchases for record keeping
app.post('/Admin/events/delete/:id', (req, res) => {
  const eventId = req.params.id;
  const admin = req.session.admin;
  if (!admin) return res.status(401).send('Unauthorized');

  // Start a transaction to ensure data consistency
  connection.beginTransaction((err) => {
    if (err) {
      console.error('Error starting transaction:', err);
      return res.status(500).send('Error deleting event');
    }

    // Step 1: Mark the event as deleted instead of actually deleting it
    // Add a 'deleted' column to your event table if you don't have one
    const markEventDeleted = 'UPDATE event SET deleted = TRUE WHERE EventID = ?';
    
    connection.query(markEventDeleted, [eventId], (err, result) => {
      if (err) {
        return connection.rollback(() => {
          console.error('Error marking event as deleted:', err);
          res.status(500).send('Error deleting event');
        });
      }

      if (result.affectedRows === 0) {
        return connection.rollback(() => {
          res.status(404).send('Event not found');
        });
      }

      // Step 2: Unpublish any tickets for this event (but keep the records)
      const unpublishTickets = 'UPDATE ticket SET Published = FALSE WHERE Fk_EventID = ?';
      
      connection.query(unpublishTickets, [eventId], (err) => {
        if (err) {
          return connection.rollback(() => {
            console.error('Error unpublishing tickets:', err);
            res.status(500).send('Error deleting event');
          });
        }

        // Commit the transaction
        connection.commit((err) => {
          if (err) {
            return connection.rollback(() => {
              console.error('Error committing transaction:', err);
              res.status(500).send('Error deleting event');
            });
          }
          
          console.log(`Event ${eventId} marked as deleted, tickets preserved`);
          res.redirect('/Admin/eventmanagementadmin');
        });
      });
    });
  });
});

// Updated ticket page route to handle deleted events
app.get('/Admin/ticketpage', (req, res) => {
  const admin = req.session.admin;
  if (!admin) return res.redirect('/login');

  // Updated query to show all events (including deleted ones) with ticket info
  const eventQuery = `
    SELECT 
      e.*,
      t.TicketPrice,
      t.Published
    FROM event e
    LEFT JOIN ticket t ON e.EventID = t.Fk_EventID
    ORDER BY e.deleted ASC, e.EventDate DESC
  `;

  //  UPDATED: Use TotalAmount instead of FinalAmountPaid
  const ticketStatsQuery = `
    SELECT Fk_EventID, COUNT(*) AS ticketsSold, SUM(TotalAmount) AS totalEarned
    FROM ticketpurchase
    GROUP BY Fk_EventID
  `;

  connection.query(eventQuery, (err, events) => {
    if (err) {
      console.error('Error retrieving events:', err);
      return res.status(500).send('Error retrieving events');
    }

    connection.query(ticketStatsQuery, (err2, ticketStats) => {
      if (err2) {
        console.error('Error retrieving ticket stats:', err2);
        return res.status(500).send('Error retrieving ticket stats');
      }

      const statsMap = {};
      ticketStats.forEach(row => {
        statsMap[row.Fk_EventID] = {
          ticketsSold: row.ticketsSold,
          totalEarned: row.totalEarned
        };
      });

      const eventsWithStats = events.map(e => ({
        ...e,
        ticketsSold: statsMap[e.EventID]?.ticketsSold || 0,
        moneyEarned: statsMap[e.EventID]?.totalEarned || 0
      }));

      res.render('ticketpageadmin', { events: eventsWithStats, admin });
    });
  });
});

// Updated event management route to exclude deleted events
app.get('/Admin/eventmanagementadmin', (req, res) => {
  // Only show non-deleted events in event management
  const query = 'SELECT * FROM event WHERE deleted IS NULL OR deleted = FALSE';
  connection.query(query, (err, events) => {
    if (err) {
      console.error('Error retrieving events:', err);
      return res.status(500).send('Internal server error');
    }

    // Convert relevant fields - UPDATED to handle new Start_Time and End_Time fields
    events = events.map(event => {
      return {
        ...event,
        EventDate: event.EventDate ? new Date(event.EventDate) : null,
        // For TIME fields, keep them as strings (MySQL returns them as strings)
        Start_Time: event.Start_Time || null,
        End_Time: event.End_Time || null,
      };
    });

    res.render('eventmanagementadmin', { 
      events,
      admin: req.session.admin || {}
    });
  });
});


app.post('/Admin/make-ticket/:eventId', (req, res) => {
  const admin = req.session.admin;
  if (!admin) return res.redirect('/login');

  const eventId = req.params.eventId;
  const price = parseFloat(req.body.ticketPrice);

  if (!price || isNaN(price)) {
    return res.status(400).send('Ticket price is required and must be a valid number');
  }

  const checkQuery = 'SELECT * FROM ticket WHERE Fk_EventID = ?';
  const insertQuery = 'INSERT INTO ticket (Fk_EventID, TicketPrice, Published) VALUES (?, ?, FALSE)';
  const updateQuery = 'UPDATE ticket SET TicketPrice = ? WHERE Fk_EventID = ?';

  connection.query(checkQuery, [eventId], (err, result) => {
    if (err) {
      console.error('Check ticket error:', err);
      return res.status(500).send('Database error');
    }

    if (result.length > 0) {
      connection.query(updateQuery, [price, eventId], (err2) => {
        if (err2) {
          console.error('Update ticket error:', err2);
          return res.status(500).send('Database error');
        }
        res.redirect('/Admin/ticketpage');
      });
    } else {
      connection.query(insertQuery, [eventId, price], (err2) => {
        if (err2) {
          console.error('Insert ticket error:', err2);
          return res.status(500).send('Database error');
        }
        res.redirect('/Admin/ticketpage');
      });
    }
  });
});


app.post('/Admin/publish-ticket/:eventId', (req, res) => {
  const admin = req.session.admin;
  if (!admin) return res.redirect('/login');

  const eventId = req.params.eventId;

  const updateQuery = 'UPDATE ticket SET Published = TRUE WHERE Fk_EventID = ?';

  connection.query(updateQuery, [eventId], (err) => {
    if (err) {
      console.error('Error publishing ticket:', err);
      return res.status(500).send('Database error');
    }
    res.redirect('/Admin/ticketpage');
  });
});



app.post('/Admin/update-capacity/:eventId', (req, res) => {
  const { eventId } = req.params;
  const { newCapacity } = req.body;

  const sql = 'UPDATE event SET Capacity = ? WHERE EventID = ?';
  connection.query(sql, [newCapacity, eventId], (err) => {
    if (err) {
      console.error('Error updating capacity:', err);
      return res.status(500).send('Failed to update capacity');
    }
    res.redirect('/Admin/ticketpage');
  });
});

app.post('/Admin/unpublish-ticket/:eventId', (req, res) => {
  const admin = req.session.admin;
  if (!admin) return res.redirect('/login');

  const eventId = req.params.eventId;

  const updateQuery = 'UPDATE ticket SET Published = FALSE WHERE Fk_EventID = ?';

  connection.query(updateQuery, [eventId], (err) => {
    if (err) {
      console.error('Error unpublishing ticket:', err);
      return res.status(500).send('Database error');
    }
    res.redirect('/Admin/ticketpage');
  });
});

// Delete ticket route - this will also delete ticket purchases
app.post('/Admin/delete-ticket/:eventId', (req, res) => {
  const admin = req.session.admin;
  if (!admin) return res.redirect('/login');

  const eventId = req.params.eventId;

  // Start transaction to ensure data consistency
  connection.beginTransaction((err) => {
    if (err) {
      console.error('Error starting transaction:', err);
      return res.status(500).send('Error deleting ticket');
    }

    // Step 1: Delete all ticket purchases for this event
    const deleteTicketPurchases = 'DELETE FROM ticketpurchase WHERE Fk_EventID = ?';
    
    connection.query(deleteTicketPurchases, [eventId], (err) => {
      if (err) {
        return connection.rollback(() => {
          console.error('Error deleting ticket purchases:', err);
          res.status(500).send('Error deleting ticket');
        });
      }

      // Step 2: Delete the ticket itself
      const deleteTicket = 'DELETE FROM ticket WHERE Fk_EventID = ?';
      
      connection.query(deleteTicket, [eventId], (err, result) => {
        if (err) {
          return connection.rollback(() => {
            console.error('Error deleting ticket:', err);
            res.status(500).send('Error deleting ticket');
          });
        }

        if (result.affectedRows === 0) {
          return connection.rollback(() => {
            res.status(404).send('Ticket not found');
          });
        }

        // Commit the transaction
        connection.commit((err) => {
          if (err) {
            return connection.rollback(() => {
              console.error('Error committing transaction:', err);
              res.status(500).send('Error deleting ticket');
            });
          }
          
          console.log(`Ticket for event ${eventId} and all purchases deleted successfully`);
          res.redirect('/Admin/ticketpage');
        });
      });
    });
  });
});

//  UPDATED: Event purchasers route with TotalAmount
app.get('/Admin/event/:id/purchasers', (req, res) => {
  const eventId = req.params.id;
  const admin = req.session.admin;
  if (!admin) return res.redirect('/login');

  //  UPDATED: Join with ticket table to get the actual ticket price
  const query = `
    SELECT 
      m.MemberID, 
      m.Member_FullName, 
      m.Member_Email, 
      tp.PurchaseDate, 
      tp.TotalAmount,
      COALESCE(t.TicketPrice, tp.TotalAmount, 0) as ActualPrice,
      t.TicketPrice as TicketTablePrice
    FROM ticketpurchase tp
    JOIN members m ON tp.fk_MemberID = m.MemberID
    JOIN event e ON tp.Fk_EventID = e.EventID
    LEFT JOIN ticket t ON e.EventID = t.Fk_EventID
    WHERE tp.Fk_EventID = ?
    ORDER BY tp.PurchaseDate DESC
  `;

  connection.query(query, [eventId], (err, results) => {
    if (err) {
      console.error('Error retrieving purchasers:', err);
      return res.status(500).send('Error loading purchasers');
    }

    //  DEBUG: Log the results to see what we're getting
    console.log('=== TICKET PURCHASERS DEBUG ===');
    console.log('Event ID:', eventId);
    console.log('Number of purchasers found:', results.length);
    
    if (results.length > 0) {
      console.log('Sample purchaser data:', results[0]);
      results.forEach((purchaser, index) => {
        console.log(`Purchaser ${index + 1}:`, {
          MemberID: purchaser.MemberID,
          TotalAmount: purchaser.TotalAmount,
          TicketTablePrice: purchaser.TicketTablePrice,
          ActualPrice: purchaser.ActualPrice
        });
      });
    }

    res.render('viewmembers', {
      admin,
      purchasers: results,
      eventId
    });
  });
});

app.get('/Member/cashback', (req, res) => {
  const email = req.session.member?.Member_Email;
  if (!email) return res.redirect('/login');
  
  // Get member details (needed for navbar)
  connection.query('SELECT * FROM members WHERE Member_Email = ?', [email], (err, results) => {
    if (err || results.length === 0) {
      return res.status(500).send('User not found');
    }
    const member = results[0];
    const memberId = member.MemberID;
    
    // Get all cashback records for this member with enhanced details
    const cashbackDetailsSql = `
      SELECT 
        CashbackID,
        Amount,
        EarnedFrom,
        EarnedDate,
        Cashback_ExpiryDate,
        fk_PurchaseTransactionID,
        UserTransactionno,
        CASE 
          WHEN Cashback_ExpiryDate >= CURDATE() THEN 'Active'
          ELSE 'Expired'
        END as Status,
        CASE 
          WHEN Amount > 0 THEN 'Earned'
          ELSE 'Used'
        END as TransactionType,
        DATEDIFF(Cashback_ExpiryDate, CURDATE()) as DaysLeft
      FROM cashback
      WHERE fk_MemberID = ?
      ORDER BY EarnedDate DESC
    `;
    
    connection.query(cashbackDetailsSql, [memberId], (cashbackErr, cashbackResults) => {
      if (cashbackErr) {
        console.error('Error fetching cashback details:', cashbackErr);
        return res.status(500).send('Failed to load cashback details');
      }
      
      // Calculate totals properly - ONLY positive amounts for active cashback
      const activeCashback = cashbackResults
        .filter(cb => cb.Status === 'Active' && cb.Amount > 0)
        .reduce((sum, cb) => sum + parseFloat(cb.Amount || 0), 0);
      
      const expiredCashback = cashbackResults
        .filter(cb => cb.Status === 'Expired' && cb.Amount > 0)
        .reduce((sum, cb) => sum + parseFloat(cb.Amount || 0), 0);
      
      // Separate earned vs used for better analytics
      const totalEarned = cashbackResults
        .filter(cb => cb.TransactionType === 'Earned')
        .reduce((sum, cb) => sum + parseFloat(cb.Amount || 0), 0);
      
      const totalUsed = Math.abs(cashbackResults
        .filter(cb => cb.TransactionType === 'Used')
        .reduce((sum, cb) => sum + parseFloat(cb.Amount || 0), 0));
      
      // Get cashback about to expire (within 30 days)
      const expiringCashback = cashbackResults
        .filter(cb => cb.Status === 'Active' && cb.DaysLeft <= 30 && cb.Amount > 0)
        .reduce((sum, cb) => sum + parseFloat(cb.Amount || 0), 0);
      
      // Debug logging
      console.log('=== CASHBACK PAGE DEBUG ===');
      console.log('Member ID:', memberId);
      console.log('Total records:', cashbackResults.length);
      console.log('Active cashback (positive only):', activeCashback);
      console.log('Expired cashback:', expiredCashback);
      console.log('Total earned:', totalEarned);
      console.log('Total used:', totalUsed);
      console.log('Expiring soon:', expiringCashback);
      
      // Verify balance matches database
      const verifyBalanceSql = `SELECT CashbackBalance FROM members WHERE MemberID = ?`;
      connection.query(verifyBalanceSql, [memberId], (verifyErr, verifyResults) => {
        let balanceMatch = true;
        let databaseBalance = 0;
        
        if (!verifyErr && verifyResults[0]) {
          databaseBalance = parseFloat(verifyResults[0].CashbackBalance);
          const calculatedBalance = Math.round(activeCashback * 100) / 100;
          const dbBalance = Math.round(databaseBalance * 100) / 100;
          
          if (Math.abs(calculatedBalance - dbBalance) > 0.01) {
            balanceMatch = false;
            console.warn('  Balance mismatch on cashback page:');
            console.warn('  Database balance:', dbBalance);
            console.warn('  Calculated balance (positive only):', calculatedBalance);
            
            // Auto-fix the database balance to match calculated balance
            const updateBalanceSql = `UPDATE members SET CashbackBalance = ? WHERE MemberID = ?`;
            connection.query(updateBalanceSql, [calculatedBalance, memberId], (updateErr) => {
              if (!updateErr) {
                console.log(' Database balance auto-corrected to:', calculatedBalance);
                databaseBalance = calculatedBalance;
                balanceMatch = true;
              }
            });
          }
        }
        
        res.render('cashback', {
          member,
          cashbackRecords: cashbackResults,
          activeCashback: Math.round(activeCashback * 100) / 100,
          expiredCashback: Math.round(expiredCashback * 100) / 100,
          totalEarned: Math.round(totalEarned * 100) / 100,
          totalUsed: Math.round(totalUsed * 100) / 100,
          expiringCashback: Math.round(expiringCashback * 100) / 100,
          balanceMatch,
          databaseBalance: Math.round(databaseBalance * 100) / 100
        });
      });
    });
  });
});

app.get('/Admin/announcements', (req, res) => {
  const adminEmail = req.session.admin?.Admin_Email;
  if (!adminEmail) return res.redirect('/Adminlogin');

  // Get admin details from clubadmin table
  connection.query('SELECT * FROM clubadmin WHERE Admin_Email = ?', [adminEmail], (err, adminResults) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).send('Database error occurred');
    }
    
    if (adminResults.length === 0) {
      console.error('Admin not found for email:', adminEmail);
      return res.status(404).send('Admin not found');
    }
    
    const admin = adminResults[0];

    // Get all announcements with admin names from clubadmin table
    const announcementsSql = `
      SELECT 
        a.AnnouncementID,
        a.Title,
        a.Content,
        a.CreatedDate,
        a.Priority,
        a.Status,
        a.ExpiryDate,
        ca.Admin_FullName AS CreatedBy
      FROM announcements a
      LEFT JOIN clubadmin ca ON a.fk_AdminID = ca.AdminID
      ORDER BY a.CreatedDate DESC
    `;

    connection.query(announcementsSql, (announcementErr, announcements) => {
      if (announcementErr) {
        console.error('Announcements query error:', announcementErr);
        return res.status(500).send('Failed to load announcements: ' + announcementErr.message);
      }

      console.log('Announcements loaded:', announcements.length);
      console.log('Admin data:', admin);

      res.render('adminannouncements', {
        admin,
        announcements: announcements || []
      });
    });
  });
});

// Debug route to check your database structure and data
app.get('/Admin/debug-announcements', (req, res) => {
  const adminEmail = req.session.admin?.Admin_Email;
  if (!adminEmail) return res.redirect('/Adminlogin');

  // Check session data
  console.log('Session admin data:', req.session.admin);
  
  // Check if admin exists in clubadmin table
  connection.query('SELECT * FROM clubadmin WHERE Admin_Email = ?', [adminEmail], (err, adminResults) => {
    if (err) return res.status(500).send('Error: ' + err.message);
    
    // Check announcements table structure and data
    connection.query('SELECT * FROM announcements LIMIT 5', (err, announcements) => {
      if (err) return res.status(500).send('Error: ' + err.message);
      
      // Check if there are any announcements
      connection.query('SELECT COUNT(*) as count FROM announcements', (err, countResult) => {
        if (err) return res.status(500).send('Error: ' + err.message);
        
        res.json({
          sessionAdmin: req.session.admin,
          adminFoundInDB: adminResults.length > 0 ? adminResults[0] : null,
          sampleAnnouncements: announcements,
          totalAnnouncements: countResult[0].count,
          announcementsColumns: announcements.length > 0 ? Object.keys(announcements[0]) : 'No announcements found'
        });
      });
    });
  });
});

// Create announcement
app.post('/Admin/announcements/create', (req, res) => {
  const adminEmail = req.session.admin?.Admin_Email;
  if (!adminEmail) return res.redirect('/Adminlogin');

  const { title, content, priority, expiryDate } = req.body;

  // Get admin ID from clubadmin table
  connection.query('SELECT AdminID FROM clubadmin WHERE Admin_Email = ?', [adminEmail], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).send('Database error occurred');
    }
    
    if (results.length === 0) {
      console.error('Admin not found for email:', adminEmail);
      return res.status(404).send('Admin not found');
    }
    
    const adminId = results[0].AdminID;

    // Insert announcement
    const insertSql = `
      INSERT INTO announcements (Title, Content, fk_AdminID, Priority, ExpiryDate, Status, CreatedDate)
      VALUES (?, ?, ?, ?, ?, 'Active', NOW())
    `;
    
    connection.query(insertSql, [title, content, adminId, priority, expiryDate || null], (insertErr) => {
      if (insertErr) {
        console.error('Insert error:', insertErr);
        return res.status(500).send('Failed to create announcement: ' + insertErr.message);
      }
      res.redirect('/Admin/announcements');
    });
  });
});

// Toggle announcement status
app.post('/Admin/announcements/toggle/:id', (req, res) => {
  const adminEmail = req.session.admin?.Admin_Email;
  if (!adminEmail) return res.redirect('/Adminlogin');

  const announcementId = req.params.id;
  const { status } = req.body;

  // Validate status
  if (!['Active', 'Inactive'].includes(status)) {
    return res.status(400).send('Invalid status value');
  }

  const updateSql = 'UPDATE announcements SET Status = ? WHERE AnnouncementID = ?';
  connection.query(updateSql, [status, announcementId], (err, result) => {
    if (err) {
      console.error('Update error:', err);
      return res.status(500).send('Failed to update announcement: ' + err.message);
    }
    
    if (result.affectedRows === 0) {
      return res.status(404).send('Announcement not found');
    }
    
    res.redirect('/Admin/announcements');
  });
});

// Edit announcement
app.post('/Admin/announcements/edit/:id', (req, res) => {
  const adminEmail = req.session.admin?.Admin_Email;
  if (!adminEmail) return res.redirect('/Adminlogin');

  const announcementId = req.params.id;
  const { title, content, priority, expiryDate } = req.body;

  const updateSql = `
    UPDATE announcements
    SET Title = ?, Content = ?, Priority = ?, ExpiryDate = ?
    WHERE AnnouncementID = ?
  `;

  connection.query(updateSql, [title, content, priority, expiryDate || null, announcementId], (err, result) => {
    if (err) {
      console.error('Edit error:', err);
      return res.status(500).send('Failed to update announcement: ' + err.message);
    }

    if (result.affectedRows === 0) {
      return res.status(404).send('Announcement not found');
    }

    res.redirect('/Admin/announcements');
  });
});


// Delete announcement

// Delete announcement - Fixed version
app.post('/Admin/announcements/delete/:id', (req, res) => {
  const adminEmail = req.session.admin?.Admin_Email;
  if (!adminEmail) return res.redirect('/Adminlogin');

  const announcementId = req.params.id;

  // Start a transaction to ensure data consistency
  connection.beginTransaction((err) => {
    if (err) {
      console.error('Transaction start error:', err);
      return res.status(500).send('Failed to start transaction: ' + err.message);
    }

    // First, delete all calendar entries referencing this announcement
    const deleteCalendarSql = 'DELETE FROM member_calendar WHERE fk_AnnouncementID = ?';
    connection.query(deleteCalendarSql, [announcementId], (calendarErr, calendarResult) => {
      if (calendarErr) {
        return connection.rollback(() => {
          console.error('Calendar delete error:', calendarErr);
          res.status(500).send('Failed to delete calendar entries: ' + calendarErr.message);
        });
      }

      console.log(`Deleted ${calendarResult.affectedRows} calendar entries for announcement ${announcementId}`);

      // Then delete the announcement itself
      const deleteAnnouncementSql = 'DELETE FROM announcements WHERE AnnouncementID = ?';
      connection.query(deleteAnnouncementSql, [announcementId], (announcementErr, announcementResult) => {
        if (announcementErr) {
          return connection.rollback(() => {
            console.error('Announcement delete error:', announcementErr);
            res.status(500).send('Failed to delete announcement: ' + announcementErr.message);
          });
        }

        if (announcementResult.affectedRows === 0) {
          return connection.rollback(() => {
            res.status(404).send('Announcement not found');
          });
        }

        // Commit the transaction
        connection.commit((commitErr) => {
          if (commitErr) {
            return connection.rollback(() => {
              console.error('Commit error:', commitErr);
              res.status(500).send('Failed to commit transaction: ' + commitErr.message);
            });
          }

          console.log(`Successfully deleted announcement ${announcementId} and related calendar entries`);
          res.redirect('/Admin/announcements');
        });
      });
    });
  });
});
app.get('/Member/calendar', isMemberLoggedIn, async (req, res) => {
  const memberID = req.session.member.MemberID;
  
  console.log("=== SEPARATED CALENDAR ROUTE ===");
  console.log("MemberID:", memberID);

  try {
    // Get announcements that were added to calendar (including expired/inactive ones)
    const [announcementRows] = await connection.promise().query(`
      SELECT
        a.AnnouncementID AS id,
        a.Title AS title,
        a.Content,
        a.CreatedDate AS start,
        a.Priority,
        a.Status,
        a.ExpiryDate,
        CASE 
          WHEN a.Status = 'Inactive' OR (a.ExpiryDate IS NOT NULL AND a.ExpiryDate < CURDATE()) 
          THEN 1 
          ELSE 0 
        END AS is_expired_or_inactive
      FROM member_calendar ma
      JOIN announcements a ON ma.fk_AnnouncementID = a.AnnouncementID
      WHERE ma.fk_MemberID = ?
      ORDER BY 
        is_expired_or_inactive ASC, -- Show active ones first
        a.CreatedDate DESC
    `, [memberID]);

    console.log('Announcement rows:', announcementRows.length);

    const announcementEvents = announcementRows.map(row => {
      const now = new Date();
      const expiry = row.ExpiryDate ? new Date(row.ExpiryDate) : null;
      const isExpired = expiry && expiry < now;
      const isInactive = row.Status && row.Status.toLowerCase() === 'inactive';
      const isExpiredOrInactive = isExpired || isInactive;

      return {
        id: `a-${row.id}`,
        title: `Announcement${isExpiredOrInactive ? ' (Expired)' : ''}`,
        start: row.start,  // Only use CreatedDate
        end: row.start,    // Set end to same as start
        content: row.Content,
        priority: row.Priority,
        status: row.Status,
        expiry: row.ExpiryDate,
        originalTitle: row.title, // Store original title for modal display
        type: 'Announcement',
        allDay: true,
        expired: isExpiredOrInactive,
        color: isExpiredOrInactive ? '#dc3545' : '#ffc107',
        textColor: isExpiredOrInactive ? '#fff' : '#000'
      };
    });

    // Rest of the code remains the same...
    
    // Get only CONFIRMED bookings
    const [bookingRows] = await connection.promise().query(`
      SELECT BookingID AS id, BookingDate, StartTime, EndTime, Status
      FROM booking
      WHERE fk_MemberID = ? AND Status = 'Confirmed'
      ORDER BY BookingDate, StartTime
    `, [memberID]);

    console.log('Confirmed booking rows:', bookingRows.length);

    const bookingEvents = bookingRows.map(b => ({
      id: `b-${b.id}`,
      title: `Booking`,
      start: `${b.BookingDate}T${b.StartTime}`,
      end: `${b.BookingDate}T${b.EndTime}`,
      status: b.Status,
      type: 'Booking',
      allDay: false,
      color: '#0d6efd',
      textColor: '#fff'
    }));

    // Separate expired/inactive announcements for logging
    const activeAnnouncements = announcementEvents.filter(event => !event.expired);
    const expiredAnnouncements = announcementEvents.filter(event => event.expired);

    console.log('=== CALENDAR DATA SUMMARY ===');
    console.log('Active announcements in calendar:', activeAnnouncements.length);
    console.log('Expired/Inactive announcements in calendar:', expiredAnnouncements.length);
    console.log('Total announcements in calendar:', announcementEvents.length);
    console.log('Confirmed bookings:', bookingEvents.length);
    console.log('Total events:', announcementEvents.length + bookingEvents.length);
    console.log('===============================');

    res.render('calendar', {
      announcementEvents, // Separate announcements (includes expired)
      bookingEvents,      // Separate bookings
      allEvents: [...announcementEvents, ...bookingEvents], // Combined for backward compatibility
      member: req.session.member
    });

  } catch (err) {
    console.error('=== CALENDAR ERROR ===');
    console.error('Error message:', err.message);
    console.error('Error code:', err.code);
    console.error('SQL:', err.sql);
    console.error('======================');
    
    res.render('calendar', {
      announcementEvents: [],
      bookingEvents: [],
      allEvents: [],
      member: req.session.member,
      error: err.message
    });
  }
});


app.post('/Member/calendar/add', isMemberLoggedIn, async (req, res) => {
  const memberID = req.session.member?.MemberID;
  const { announcementID } = req.body;

  console.log("== POST /Member/calendar/add ==");
  console.log("MemberID:", memberID);
  console.log("AnnouncementID:", announcementID);

  if (!announcementID || !memberID) {
    console.log("Missing data - AnnouncementID:", announcementID, "MemberID:", memberID);
    return res.status(400).send("Invalid request: Missing announcement ID or not logged in.");
  }

  try {
    // Check if already exists
    const [existing] = await connection.promise().query(
      `SELECT * FROM member_calendar WHERE fk_MemberID = ? AND fk_AnnouncementID = ?`,
      [memberID, announcementID]
    );

    console.log("Existing entries found:", existing.length);

    if (existing.length > 0) {
      console.log("Already in calendar, skipping insert.");
      return res.redirect('/Member/calendar');
    }

    // Verify announcement exists
    const [announcementCheck] = await connection.promise().query(
      `SELECT AnnouncementID, Title FROM announcements WHERE AnnouncementID = ?`,
      [announcementID]
    );
    
    console.log("Announcement check:", announcementCheck);
    
    if (announcementCheck.length === 0) {
      console.log("ERROR: Announcement not found!");
      return res.status(400).send("Announcement not found.");
    }

    // Insert into calendar
    console.log("About to insert with values:", [memberID, announcementID]);
    const [result] = await connection.promise().query(
      `INSERT INTO member_calendar (fk_MemberID, fk_AnnouncementID, AddedDate)
       VALUES (?, ?, CURDATE())`,
      [memberID, announcementID]
    );

    console.log("Insert successful! Result:", result);

    return res.redirect('/Member/calendar');

  } catch (err) {
    console.error("=== INSERT ERROR ===");
    console.error("Error message:", err.message);
    console.error("Error code:", err.code);
    console.error("MemberID:", memberID);
    console.error("AnnouncementID:", announcementID);
    console.error("===================");
    return res.status(500).send(`Server error while adding to calendar: ${err.message}`);
  }
});

// Route to remove announcement from member's calendar
app.post('/Member/calendar/remove-announcement', isMemberLoggedIn, async (req, res) => {
  const memberID = req.session.member.MemberID;
  const { announcementId } = req.body;
  
  console.log("=== REMOVE ANNOUNCEMENT FROM CALENDAR ===");
  console.log("MemberID:", memberID);
  console.log("AnnouncementID:", announcementId);

  try {
    // Validate input
    if (!announcementId) {
      return res.status(400).json({
        success: false,
        message: 'Announcement ID is required'
      });
    }

    // Check if the announcement exists in the member's calendar
    const [checkRows] = await connection.promise().query(`
      SELECT ma.*, a.Title, a.Status, a.ExpiryDate
      FROM member_calendar ma
      JOIN announcements a ON ma.fk_AnnouncementID = a.AnnouncementID
      WHERE ma.fk_MemberID = ? AND ma.fk_AnnouncementID = ?
    `, [memberID, announcementId]);

    if (checkRows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Announcement not found in your calendar'
      });
    }

    const announcement = checkRows[0];
    console.log('Found announcement:', announcement.Title);
    console.log('Status:', announcement.Status);
    console.log('Expiry:', announcement.ExpiryDate);

    // Remove the announcement from member's calendar
    const [deleteResult] = await connection.promise().query(`
      DELETE FROM member_calendar 
      WHERE fk_MemberID = ? AND fk_AnnouncementID = ?
    `, [memberID, announcementId]);

    if (deleteResult.affectedRows > 0) {
      console.log('Successfully removed announcement from calendar');
      
      res.json({
        success: true,
        message: 'Announcement removed from calendar successfully',
        removedTitle: announcement.Title
      });
    } else {
      console.log('No rows affected during deletion');
      res.status(500).json({
        success: false,
        message: 'Failed to remove announcement from calendar'
      });
    }

  } catch (err) {
    console.error('=== REMOVE ANNOUNCEMENT ERROR ===');
    console.error('Error message:', err.message);
    console.error('Error code:', err.code);
    console.error('SQL:', err.sql);
    console.error('=====================================');
    
    res.status(500).json({
      success: false,
      message: 'Database error occurred while removing announcement',
      error: err.message
    });
  }
});


app.get('/Member/calendar/debug', isMemberLoggedIn, async (req, res) => {
  const memberID = req.session.member.MemberID;
  
  try {
    // Check member_calendar contents
    const [memberCalendarRows] = await connection.promise().query(
      `SELECT * FROM member_calendar WHERE fk_MemberID = ?`,
      [memberID]
    );
    
    // Check announcements
    const [announcementRows] = await connection.promise().query(
      `SELECT AnnouncementID, Title, CreatedDate FROM announcements LIMIT 5`
    );
    
    console.log("=== DEBUG INFO ===");
    console.log("MemberID:", memberID);
    console.log("Member calendar entries:", memberCalendarRows);
    console.log("Available announcements:", announcementRows);
    console.log("==================");
    
    res.json({
      memberID,
      memberCalendarRows,
      announcementRows
    });
    
  } catch (err) {
    console.error("Debug error:", err);
    res.status(500).json({ error: err.message });
  }
});




// Start server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
