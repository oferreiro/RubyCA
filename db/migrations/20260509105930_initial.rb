Sequel.migration do
  up do
    create_table(:certificate_schemas) do
      primary_key :id
      String :o, :size=>64
      String :l, :size=>64
      String :st, :size=>64
      String :c, :size=>64
    end
    
    create_table(:certificates) do
      primary_key :id
      String :cn, :size=>64, :null=>false
      String :crt, :text=>true
      String :pkey, :text=>true
      index :cn, :unique=>true
    end
    
    create_table(:configs) do
      primary_key :id
      String :name, :size=>50, :null=>false
      String :value, :size=>50, :null=>false
      index :name, :unique=>true
    end
    
    create_table(:crls) do
      primary_key :id
      String :data, :text=>true
      foreign_key :certificate_id, :certificates, unique: true, null: false
    end
    
    create_table(:csrs) do
      primary_key :id
      String :cn, :size=>64, :null=>false
      String :o, :size=>64, :null=>false
      String :l, :size=>64, :null=>false
      String :st, :size=>64, :null=>false
      String :c, :size=>64, :null=>false
      String :csr, :text=>true
      String :pkey, :text=>true
      index :cn, :unique=>true
    end
    
    create_table(:revokeds) do
      primary_key :id
      String :cn, :size=>64
      String :crt, :text=>true
      String :pkey, :text=>true
    end
  end

  down do
    drop_table(:certificate_schemas)
    drop_table(:certificates)
    drop_table(:configs)
    drop_table(:crls)
    drop_table(:csrs)
    drop_table(:revokeds)
  end
end
